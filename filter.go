package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"github.com/oschwald/maxminddb-golang"
)

type rateEntry struct {
	count     int
	timestamp time.Time
}

const (
	iface              = "ens33"
	geoIPDB            = "/app/GeoLite2-Country.mmdb"
	logFile            = "/app/filter.log" // Изменил путь на /app/filter.log
	rateLimit          = 100
	rateLimitWindow    = time.Minute
	tblDuration        = 10 * time.Minute
	maxTCPSessions     = 50
	wsUpdateInterval   = 1 * time.Second
	tblCleanupInterval = 5 * time.Minute
)

const (
	whitelistFile = "/etc/filter/whitelist.txt"
	blacklistFile = "/etc/filter/blacklist.txt"
	tblFile       = "/etc/filter/tbl.txt"
	fzoFile       = "/etc/filter/fzo.txt"
)

var (
	allowedCountry    string
	whitelist         = make(map[string]bool)
	blacklist         = make(map[string]bool)
	fzoRules          = make(map[string]bool)
	tcpSessions       = make(map[string]int)
	actions           = make(map[string]struct {
		Action      string
		TBLDuration time.Duration
	})
	shapingRules      = make(map[string]string)
	trafficStats = struct {
		IncomingBytes int64
		PassedBytes   int64
		DroppedBytes  map[string]int64
		sync.RWMutex
	}{
		DroppedBytes: make(map[string]int64),
	}
	mutex      = &sync.RWMutex{}
	logFilePtr *os.File
	geoDB      *maxminddb.Reader
	wsClients  = make(map[*websocket.Conn]bool)
	wsMutex    = &sync.RWMutex{}
	rateLimitMap = make(map[string]rateEntry)
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func initLogs() {
	log.Println("Инициализация логов...")
	var err error
	logFilePtr, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) // Вернул err
	if err != nil {
		log.Fatalf("Ошибка открытия лога: %v", err)
	}
	log.SetOutput(logFilePtr)
	log.Println("Логи успешно инициализированы")
}

func initGeoIP() {
	log.Println("Инициализация GeoIP...")
	var err error
	geoDB, err = maxminddb.Open(geoIPDB)
	if err != nil {
		log.Fatalf("Ошибка открытия GeoLite2: %v", err)
	}
	log.Println("GeoIP успешно инициализирован")
}

func initIPTables() {
	log.Println("Инициализация iptables...")
	chains := []string{"WL_CHAIN", "BL_CHAIN", "TBL_CHAIN", "GEOIP_CHAIN", "CLEANUP_CHAIN", "FZO_CHAIN", "ZOMBIE_CHAIN", "TCP_AUTH_CHAIN", "TCP_SESSIONS_CHAIN", "SHAPING_CHAIN"}
	for _, chain := range chains {
		cmd := exec.Command("iptables", "-N", chain)
		if err := cmd.Run(); err != nil {
			log.Printf("IPTables chain %s creation error: %v", chain, err)
		}
	}
	iptablesRules := []string{
		"-A FORWARD -j WL_CHAIN",
		"-A FORWARD -j BL_CHAIN",
		"-A FORWARD -j TBL_CHAIN",
		"-A FORWARD -j GEOIP_CHAIN",
		"-A FORWARD -j CLEANUP_CHAIN",
		"-A FORWARD -j FZO_CHAIN",
		"-A FORWARD -j ZOMBIE_CHAIN",
		"-A FORWARD -j TCP_AUTH_CHAIN",
		"-A FORWARD -j TCP_SESSIONS_CHAIN",
		"-A FORWARD -j SHAPING_CHAIN",
	}
	for _, rule := range iptablesRules {
		cmd := exec.Command("iptables", strings.Split(rule, " ")...)
		if err := cmd.Run(); err != nil {
			log.Printf("IPTables rule %s error: %v", rule, err)
		}
	}
	log.Println("iptables успешно инициализирован")
}

func loadLists() {
	log.Println("Загрузка списков...")
	mutex.Lock()
	defer mutex.Unlock()
	whitelist = make(map[string]bool)
	if file, err := os.Open(whitelistFile); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				whitelist[ip] = true
			}
		}
	} else {
		log.Printf("Ошибка открытия whitelist: %v", err)
	}

	blacklist = make(map[string]bool)
	if file, err := os.Open(blacklistFile); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				blacklist[ip] = true
				applyIPTablesBlock(ip, "BL", "BL_CHAIN")
			}
		}
	} else {
		log.Printf("Ошибка открытия blacklist: %v", err)
	}

	fzoRules = make(map[string]bool)
	if file, err := os.Open(fzoFile); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			parts := strings.Fields(strings.TrimSpace(scanner.Text()))
			if len(parts) == 2 {
				port, proto := parts[0], parts[1]
				fzoRules[port+"_"+proto] = true
				applyFZORule(port, proto)
			}
		}
	} else {
		log.Printf("Ошибка открытия fzo: %v", err)
	}
	log.Println("Списки успешно загружены")
}

func saveList(filename string, entries map[string]bool) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for entry := range entries {
		fmt.Fprintln(writer, entry)
	}
	return writer.Flush()
}

func saveFZO() error {
	file, err := os.Create(fzoFile)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for rule := range fzoRules {
		parts := strings.Split(rule, "_")
		if len(parts) == 2 {
			fmt.Fprintf(writer, "%s %s\n", parts[0], parts[1])
		}
	}
	return writer.Flush()
}

func saveTBL(entries map[string]struct {
	Reason      string
	TimeAdded   int64
	Duration    int64
}) error {
	file, err := os.Create(tblFile)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for ip, info := range entries {
		fmt.Fprintf(writer, "%s # %s %d %d\n", ip, info.Reason, info.TimeAdded, info.Duration)
	}
	return writer.Flush()
}

func cleanupTBL() {
	for {
		mutex.Lock()
		entries := make(map[string]struct {
			Reason      string
			TimeAdded   int64
			Duration    int64
		})
		if file, err := os.Open(tblFile); err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, "#", 2)
				ip := strings.TrimSpace(parts[0])
				if ip == "" || len(parts) < 2 {
					continue
				}
				fields := strings.Fields(parts[1])
				if len(fields) < 3 {
					continue
				}
				reason, timeAddedStr, durationStr := fields[0], fields[1], fields[2]
				timeAdded, _ := strconv.ParseInt(timeAddedStr, 10, 64)
				duration, _ := strconv.ParseInt(durationStr, 10, 64)
				if time.Now().Unix()-timeAdded < duration {
					entries[ip] = struct {
						Reason      string
						TimeAdded   int64
						Duration    int64
					}{reason, timeAdded, duration}
				}
			}
			file.Close()
		}
		saveTBL(entries)
		mutex.Unlock()
		time.Sleep(tblCleanupInterval)
	}
}

func loadActions() {
	log.Println("Загрузка действий...")
	actions = map[string]struct {
		Action      string
		TBLDuration time.Duration
	}{
		"Zombie":      {"TBL", 600 * time.Second},
		"Cleanup":     {"DROP", 0},
		"FZO":         {"DROP", 0},
		"TCPAuth":     {"DROP", 0},
		"TCPSessions": {"DROP", 0},
		"Shaping":     {"DROP", 0},
	}
	log.Println("Действия успешно загружены")
}

func logEvent(clientIP string, port int, protocol, countermeasure, action, reason, reasonCountermeasure string, bytes int64) {
	trafficStats.Lock()
	if countermeasure == "Passed" {
		trafficStats.PassedBytes += bytes
	} else {
		key := countermeasure
		if reasonCountermeasure != "" && countermeasure == "TBL" {
			key = fmt.Sprintf("TBL_%s", reasonCountermeasure)
		}
		trafficStats.DroppedBytes[key] += bytes
	}
	trafficStats.Unlock()

	logEntry := fmt.Sprintf("%s | IP: %s | Port: %d | Proto: %s | Countermeasure: %s | Action: %s | Reason: %s | ReasonCM: %s | Bytes: %d",
		time.Now().Format(time.RFC3339), clientIP, port, protocol, countermeasure, action, reason, reasonCountermeasure, bytes)
	mutex.Lock()
	fmt.Fprintln(logFilePtr, logEntry)
	logFilePtr.Sync()
	mutex.Unlock()
}

func applyAction(clientIP, countermeasure, reason, reasonCountermeasure string, port int, protocol string, bytes int64) bool {
	mutex.RLock()
	actionConfig, exists := actions[countermeasure]
	mutex.RUnlock()
	if !exists {
		logEvent(clientIP, port, protocol, countermeasure, "DROP", reason, reasonCountermeasure, bytes)
		return false
	}
	switch actionConfig.Action {
	case "DROP":
		logEvent(clientIP, port, protocol, countermeasure, "DROP", reason, reasonCountermeasure, bytes)
		return false
	case "TBL":
		addToTBL(clientIP, actionConfig.TBLDuration, countermeasure)
		logEvent(clientIP, port, protocol, "TBL", "TBL", reason, countermeasure, bytes)
		return false
	case "BL":
		mutex.Lock()
		blacklist[clientIP] = true
		mutex.Unlock()
		applyIPTablesBlock(clientIP, "BL", "BL_CHAIN")
		saveList(blacklistFile, blacklist)
		logEvent(clientIP, port, protocol, countermeasure, "BL", reason, countermeasure, bytes)
		return false
	default:
		logEvent(clientIP, port, protocol, countermeasure, "DROP", reason, reasonCountermeasure, bytes)
		return false
	}
}

func checkRateLimit(ip string) bool {
	mutex.Lock()
	defer mutex.Unlock()
	if rateLimitMap == nil {
		rateLimitMap = make(map[string]rateEntry)
	}
	entry, exists := rateLimitMap[ip]
	if !exists || time.Since(entry.timestamp) > rateLimitWindow {
		rateLimitMap[ip] = rateEntry{count: 1, timestamp: time.Now()}
		return true
	}
	if entry.count >= rateLimit {
		return false
	}
	rateLimitMap[ip] = rateEntry{count: entry.count + 1, timestamp: entry.timestamp}
	return true
}

func checkTBL(ip string) (bool, string) {
	file, err := os.Open(tblFile)
	if err != nil {
		log.Printf("Ошибка открытия файла TBL: %v", err)
		return false, ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "#", 2)
		entryIP := strings.TrimSpace(parts[0])
		if entryIP != ip || len(parts) < 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 3 {
			continue
		}
		reason, timeAddedStr, durationStr := fields[0], fields[1], fields[2]
		timeAdded, _ := strconv.ParseInt(timeAddedStr, 10, 64)
		duration, _ := strconv.ParseInt(durationStr, 10, 64)
		if time.Now().Unix()-timeAdded < duration {
			return true, reason
		}
	}
	return false, ""
}

func addToTBL(ip string, duration time.Duration, reason string) {
	mutex.Lock()
	defer mutex.Unlock()

	entries := make(map[string]struct {
		Reason      string
		TimeAdded   int64
		Duration    int64
	})
	file, err := os.Open(tblFile)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "#", 2)
			entryIP := strings.TrimSpace(parts[0])
			if entryIP == "" || len(parts) < 2 {
				continue
			}
			fields := strings.Fields(parts[1])
			if len(fields) < 3 {
				continue
			}
			entryReason, timeAddedStr, durationStr := fields[0], fields[1], fields[2]
			timeAdded, _ := strconv.ParseInt(timeAddedStr, 10, 64)
			duration, _ := strconv.ParseInt(durationStr, 10, 64)
			if time.Now().Unix()-timeAdded < duration {
				entries[entryIP] = struct {
					Reason      string
					TimeAdded   int64
					Duration    int64
				}{entryReason, timeAdded, duration}
			}
		}
		file.Close()
	}

	entries[ip] = struct {
		Reason      string
		TimeAdded   int64
		Duration    int64
	}{reason, time.Now().Unix(), int64(duration / time.Second)}
	saveTBL(entries)
	applyIPTablesBlock(ip, "TBL", "TBL_CHAIN")
}

func checkGeoIP(ip string) bool {
	if allowedCountry == "" {
		return true
	}
	var record struct{ Country struct{ ISOCode string } }
	err := geoDB.Lookup(net.ParseIP(ip), &record)
	if err != nil {
		log.Printf("Ошибка GeoIP: %v", err)
		return false
	}
	return record.Country.ISOCode == allowedCountry
}

func basicCleanup(packet gopacket.Packet) bool {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer == nil {
		return false
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && tcp.ACK {
			return false
		}
	}
	return true
}

func tcpAuth(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			return true
		}
	}
	return true
}

func checkTCPSessions(ip string) bool {
	mutex.Lock()
	defer mutex.Unlock()
	tcpSessions[ip]++
	if tcpSessions[ip] > maxTCPSessions {
		return false
	}
	return true
}

func applyIPTablesBlock(ip, prefix, chain string) {
	cmd := exec.Command("iptables", "-A", chain, "-s", ip, "-j", "LOG", "--log-prefix", fmt.Sprintf("%s_BLOCK: ", prefix))
	if err := cmd.Run(); err != nil {
		log.Printf("Ошибка IPTables: %v", err)
	}
	cmd = exec.Command("iptables", "-A", chain, "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("Ошибка IPTables: %v", err)
	}
}

func applyFZORule(port, proto string) {
	cmd := exec.Command("iptables", "-A", "FZO_CHAIN", "-p", proto, "--sport", port, "-j", "LOG", "--log-prefix", "FZO_BLOCK: ")
	if err := cmd.Run(); err != nil {
		log.Printf("Ошибка IPTables FZO: %v", err)
	}
	cmd = exec.Command("iptables", "-A", "FZO_CHAIN", "-p", proto, "--sport", port, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("Ошибка IPTables FZO: %v", err)
	}
}

func applyShaping(ip, rate string) {
	mutex.Lock()
	shapingRules[ip] = rate
	mutex.Unlock()

	cmd := exec.Command("iptables", "-A", "SHAPING_CHAIN", "-s", ip, "-j", "LOG", "--log-prefix", "SHAPING_BLOCK: ")
	if err := cmd.Run(); err != nil {
		log.Printf("Ошибка IPTables shaping: %v", err)
	}
	cmd = exec.Command("tc", "qdisc", "add", "dev", iface, "root", "tbf", "rate", rate, "burst", "32kbit", "latency", "400ms")
	if err := cmd.Run(); err != nil {
		log.Printf("Ошибка TC: %v", err)
	}
}

func handlePackets() {
	log.Println("Запуск обработки пакетов...")
	if _, err := net.InterfaceByName(iface); err != nil {
		log.Printf("Ошибка: интерфейс %s недоступен: %v", iface, err)
		return
	}
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Ошибка открытия интерфейса %s: %v", iface, err)
		return
	}
	defer handle.Close()

	log.Printf("Начало обработки пакетов на интерфейсе %s", iface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		log.Println("Обработка нового пакета...")
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			log.Println("Пакет без IPv4, пропуск")
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		clientIP := ip.SrcIP.String()
		protocol := ip.Protocol.String()
		port := 0
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			port = int(tcp.SrcPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			port = int(udp.SrcPort)
		}
		bytes := int64(len(packet.Data()))

		trafficStats.Lock()
		trafficStats.IncomingBytes += bytes
		log.Printf("Добавлено входящих байт: %d, всего: %d", bytes, trafficStats.IncomingBytes)
		trafficStats.Unlock()

		mutex.RLock()
		if len(whitelist) > 0 && !whitelist[clientIP] {
			mutex.RUnlock()
			logEvent(clientIP, port, protocol, "WL", "DROP", "Не в белом списке", "", bytes)
			continue
		}
		mutex.RUnlock()

		mutex.RLock()
		if blacklist[clientIP] {
			mutex.RUnlock()
			logEvent(clientIP, port, protocol, "BL", "DROP", "IP в чёрном списке", "", bytes)
			continue
		}
		mutex.RUnlock()

		if blocked, reason := checkTBL(clientIP); blocked {
			logEvent(clientIP, port, protocol, "TBL", "DROP", "Временно заблокировано", reason, bytes)
			continue
		}

		if !checkGeoIP(clientIP) {
			logEvent(clientIP, port, protocol, "GeoIP", "DROP", "Заблокировано по стране", "", bytes)
			continue
		}

		if !basicCleanup(packet) {
			if !applyAction(clientIP, "Cleanup", "Недопустимый пакет", "", port, protocol, bytes) {
				continue
			}
		}

		mutex.RLock()
		for rule := range fzoRules {
			parts := strings.Split(rule, "_")
			if len(parts) == 2 {
				fzoPort, fzoProto := parts[0], parts[1]
				if fmt.Sprintf("%d", port) == fzoPort && strings.ToLower(protocol) == strings.ToLower(fzoProto) {
					mutex.RUnlock()
					if !applyAction(clientIP, "FZO", fmt.Sprintf("Порт %s заблокирован", fzoPort), "", port, protocol, bytes) {
						continue
					}
				}
			}
		}
		mutex.RUnlock()

		if !checkRateLimit(clientIP) {
			if !applyAction(clientIP, "Zombie", "Превышен лимит скорости", "", port, protocol, bytes) {
				continue
			}
		}

		if !tcpAuth(packet) {
			if !applyAction(clientIP, "TCPAuth", "Недопустимый TCP-пакет", "", port, protocol, bytes) {
				continue
			}
		}

		if !checkTCPSessions(clientIP) {
			if !applyAction(clientIP, "TCPSessions", "Слишком много TCP-сессий", "", port, protocol, bytes) {
				continue
			}
		}

		logEvent(clientIP, port, protocol, "Passed", "ACCEPT", "Пакет пропущен", "", bytes)
	}
}

func handleWebSocket(c *gin.Context) {
	log.Println("Подключение к WebSocket...")
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Ошибка WebSocket: %v", err)
		return
	}

	wsMutex.Lock()
	wsClients[conn] = true
	wsMutex.Unlock()

	defer func() {
		wsMutex.Lock()
		delete(wsClients, conn)
		wsMutex.Unlock()
		conn.Close()
	}()

	log.Println("Клиент подключился к WebSocket")
	for {
		trafficStats.RLock()
		data := map[string]interface{}{
			"Incoming": trafficStats.IncomingBytes,
			"Passed":   trafficStats.PassedBytes,
			"Dropped":  trafficStats.DroppedBytes,
		}
		trafficStats.RUnlock()

		log.Printf("Отправка данных через WebSocket: %v", data)
		if err := conn.WriteJSON(data); err != nil {
			log.Printf("Ошибка записи в WebSocket: %v", err)
			break
		}
		time.Sleep(wsUpdateInterval)
	}
}

func manageRules(c *gin.Context) {
	log.Println("Управление правилами...")
	type Rule struct {
		IP       string `json:"ip"`
		ListType string `json:"listType"`
		Port     string `json:"port"`
		Proto    string `json:"proto"`
		Rate     string `json:"rate"`
		Action   string `json:"action"`
		Duration int    `json:"duration"`
	}

	var rule Rule
	if err := c.BindJSON(&rule); err != nil {
		log.Printf("Недопустимый запрос: %v", err)
		c.String(http.StatusBadRequest, "Недопустимый запрос")
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	switch rule.ListType {
	case "whitelist":
		if rule.Action == "add" {
			whitelist[rule.IP] = true
			saveList(whitelistFile, whitelist)
			logEvent(rule.IP, 0, "", "WL", "Добавлено", "Добавлено в белый список", "", 0)
			c.String(http.StatusOK, "IP %s добавлен в белый список", rule.IP)
		} else if rule.Action == "remove" {
			delete(whitelist, rule.IP)
			saveList(whitelistFile, whitelist)
			logEvent(rule.IP, 0, "", "WL", "Удалено", "Удалено из белого списка", "", 0)
			c.String(http.StatusOK, "IP %s удалён из белого списка", rule.IP)
		}
	case "blacklist":
		if rule.Action == "add" {
			blacklist[rule.IP] = true
			applyIPTablesBlock(rule.IP, "BL", "BL_CHAIN")
			saveList(blacklistFile, blacklist)
			logEvent(rule.IP, 0, "", "BL", "Добавлено", "Добавлено в чёрный список", "", 0)
			c.String(http.StatusOK, "IP %s добавлен в чёрный список", rule.IP)
		} else if rule.Action == "remove" {
			delete(blacklist, rule.IP)
			exec.Command("iptables", "-D", "BL_CHAIN", "-s", rule.IP, "-j", "DROP").Run()
			saveList(blacklistFile, blacklist)
			logEvent(rule.IP, 0, "", "BL", "Удалено", "Удалено из чёрного списка", "", 0)
			c.String(http.StatusOK, "IP %s удалён из чёрного списка", rule.IP)
		}
	case "tbl":
		if rule.Action == "add" {
			duration := time.Duration(rule.Duration) * time.Second
			if duration <= 0 {
				duration = tblDuration
			}
			addToTBL(rule.IP, duration, "Manual")
			logEvent(rule.IP, 0, "", "TBL", "Добавлено", "Добавлено в TBL", "Manual", 0)
			c.String(http.StatusOK, "IP %s добавлен в TBL на %d секунд", rule.IP, rule.Duration)
		} else if rule.Action == "remove" {
			entries := make(map[string]struct {
				Reason      string
				TimeAdded   int64
				Duration    int64
			})
			file, err := os.Open(tblFile)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}
					parts := strings.SplitN(line, "#", 2)
					entryIP := strings.TrimSpace(parts[0])
					if entryIP == rule.IP || len(parts) < 2 {
						continue
					}
					fields := strings.Fields(parts[1])
					if len(fields) < 3 {
						continue
					}
					entryReason, timeAddedStr, durationStr := fields[0], fields[1], fields[2]
					timeAdded, _ := strconv.ParseInt(timeAddedStr, 10, 64)
					duration, _ := strconv.ParseInt(durationStr, 10, 64)
					if time.Now().Unix()-timeAdded < duration {
						entries[entryIP] = struct {
							Reason      string
							TimeAdded   int64
							Duration    int64
						}{entryReason, timeAdded, duration}
					}
				}
				file.Close()
			}
			saveTBL(entries)
			exec.Command("iptables", "-D", "TBL_CHAIN", "-s", rule.IP, "-j", "DROP").Run()
			logEvent(rule.IP, 0, "", "TBL", "Удалено", "Удалено из TBL", "", 0)
			c.String(http.StatusOK, "IP %s удалён из TBL", rule.IP)
		}
	case "fzo":
		if rule.Action == "add" {
			fzoRules[rule.Port+"_"+rule.Proto] = true
			applyFZORule(rule.Port, rule.Proto)
			saveFZO()
			logEvent("", 0, rule.Proto, "FZO", "Добавлено", fmt.Sprintf("Порт %s заблокирован", rule.Port), "", 0)
			c.String(http.StatusOK, "Порт %s заблокирован", rule.Port)
		} else if rule.Action == "remove" {
			delete(fzoRules, rule.Port+"_"+rule.Proto)
			exec.Command("iptables", "-D", "FZO_CHAIN", "-p", rule.Proto, "--sport", rule.Port, "-j", "DROP").Run()
			saveFZO()
			logEvent("", 0, rule.Proto, "FZO", "Удалено", fmt.Sprintf("Порт %s разблокирован", rule.Port), "", 0)
			c.String(http.StatusOK, "Порт %s разблокирован", rule.Port)
		}
	case "shaping":
		if rule.Action == "add" {
			applyShaping(rule.IP, rule.Rate)
			logEvent(rule.IP, 0, "", "Shaping", "Добавлено", fmt.Sprintf("Трафик ограничен до %s", rule.Rate), "", 0)
			c.String(http.StatusOK, "Shaping применён для %s на %s", rule.IP, rule.Rate)
		} else {
			delete(shapingRules, rule.IP)
			exec.Command("tc", "qdisc", "del", "dev", iface, "root").Run()
			logEvent(rule.IP, 0, "", "Shaping", "Удалено", "Shaping удалён", "", 0)
			c.String(http.StatusOK, "Shaping удалён для %s", rule.IP)
		}
	default:
		log.Printf("Недопустимый тип списка: %s", rule.ListType)
		c.String(http.StatusBadRequest, "Недопустимый тип списка")
	}
}

func configureAction(c *gin.Context) {
	log.Println("Настройка действия...")
	type ActionConfig struct {
		Countermeasure string `json:"countermeasure"`
		Action         string `json:"action"`
		TBLDuration    int    `json:"tbl_duration"`
	}

	var config ActionConfig
	if err := c.BindJSON(&config); err != nil {
		log.Printf("Недопустимый запрос: %v", err)
		c.String(http.StatusBadRequest, "Недопустимый запрос")
		return
	}

	if config.Action != "DROP" && config.Action != "TBL" && config.Action != "BL" {
		log.Printf("Недопустимое действие: %s", config.Action)
		c.String(http.StatusBadRequest, "Недопустимое действие")
		return
	}

	mutex.Lock()
	actions[config.Countermeasure] = struct {
		Action      string
		TBLDuration time.Duration
	}{
		Action:      config.Action,
		TBLDuration: time.Duration(config.TBLDuration) * time.Second,
	}
	mutex.Unlock()

	log.Printf("Действие настроено для %s: %s", config.Countermeasure, config.Action)
	c.String(http.StatusOK, "Действие настроено для %s: %s", config.Countermeasure, config.Action)
}

func setCountry(c *gin.Context) {
	log.Println("Установка страны...")
	type CountryConfig struct {
		Country string `json:"country"`
	}
	var config CountryConfig
	if err := c.BindJSON(&config); err != nil {
		log.Printf("Недопустимый запрос: %v", err)
		c.String(http.StatusBadRequest, "Недопустимый запрос")
		return
	}

	mutex.Lock()
	allowedCountry = strings.ToUpper(config.Country)
	mutex.Unlock()

	logEvent("", 0, "", "GeoIP", "Установлена страна", fmt.Sprintf("Разрешённая страна: %s", allowedCountry), "", 0)
	c.String(http.StatusOK, "Разрешённая страна установлена: %s", allowedCountry)
}

func getCountry(c *gin.Context) {
	log.Println("Получение страны...")
	mutex.RLock()
	defer mutex.RUnlock()
	c.JSON(http.StatusOK, map[string]string{"country": allowedCountry})
}

func getLists(c *gin.Context) {
	log.Println("Получение списков...")
	mutex.RLock()
	defer mutex.RUnlock()

	fzoList := make([]map[string]string, 0)
	for rule := range fzoRules {
		parts := strings.Split(rule, "_")
		if len(parts) == 2 {
			fzoList = append(fzoList, map[string]string{"port": parts[0], "proto": parts[1]})
		}
	}

	tblList := make([]map[string]interface{}, 0)
	file, err := os.Open(tblFile)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "#", 2)
			ip := strings.TrimSpace(parts[0])
			if ip == "" || len(parts) < 2 {
				continue
			}
			fields := strings.Fields(parts[1])
			if len(fields) < 3 {
				continue
			}
			reason, timeAddedStr, durationStr := fields[0], fields[1], fields[2]
			timeAdded, _ := strconv.ParseInt(timeAddedStr, 10, 64)
			duration, _ := strconv.ParseInt(durationStr, 10, 64)
			if time.Now().Unix()-timeAdded < duration {
				tblList = append(tblList, map[string]interface{}{
					"ip":        ip,
					"reason":    reason,
					"timeAdded": timeAdded,
					"duration":  duration,
				})
			}
		}
		file.Close()
	}

	var allCountries []string
	if geoDB != nil {
		allCountries = []string{"RU", "US", "CN", "DE", "FR"}
	}

	blockedCountries := []string{}
	if allowedCountry != "" {
		for _, country := range allCountries {
			if country != allowedCountry {
				blockedCountries = append(blockedCountries, country)
			}
		}
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"whitelist":       whitelist,
		"blacklist":       blacklist,
		"fzo":             fzoList,
		"tbl":             tblList,
		"actions":         actions,
		"allowedCountry":  allowedCountry,
		"blockedCountries": blockedCountries,
		"shapingRules":    shapingRules,
	})
}

func getEvents(c *gin.Context) {
	log.Println("Получение событий...")
	file, err := os.Open(logFile)
	if err != nil {
		log.Printf("Ошибка файла логов: %v", err)
		c.String(http.StatusInternalServerError, "Ошибка файла логов")
		return
	}
	defer file.Close()

	var events []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		events = append(events, scanner.Text())
	}
	if len(events) > 100 {
		events = events[len(events)-100:]
	}
	c.JSON(http.StatusOK, events)
}

func main() {
	log.Println("Запуск приложения...")
	initLogs()
	initGeoIP()
	initIPTables()
	loadActions()
	loadLists()
	defer logFilePtr.Close()
	defer geoDB.Close()

	log.Println("Запуск горутины cleanupTBL...")
	go cleanupTBL()

	log.Println("Запуск горутины handlePackets...")
	go handlePackets()

	log.Println("Запуск горутины для WebSocket...")
	go func() {
		for {
			wsMutex.RLock()
			for conn := range wsClients {
				trafficStats.RLock()
				data := map[string]interface{}{
					"Incoming": trafficStats.IncomingBytes,
					"Passed":   trafficStats.PassedBytes,
					"Dropped":  trafficStats.DroppedBytes,
				}
				trafficStats.RUnlock()
				if err := conn.WriteJSON(data); err != nil {
					log.Printf("Ошибка отправки данных WebSocket: %v", err)
					conn.Close()
					delete(wsClients, conn)
				}
			}
			wsMutex.RUnlock()
			time.Sleep(wsUpdateInterval)
		}
	}()

	log.Println("Настройка маршрутов Gin...")
	r := gin.Default()
	r.POST("/manage", manageRules)
	r.POST("/configure", configureAction)
	r.POST("/set-country", setCountry)
	r.GET("/get-country", getCountry)
	r.GET("/lists", getLists)
	r.GET("/events", getEvents)
	r.GET("/ws", handleWebSocket)

	log.Println("Запуск сервера API на :8080...")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}
