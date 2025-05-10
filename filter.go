package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
)

const (
	iface       = "ens33"
	logFile     = "/app/filter.log"
	trafficFile = "/app/traffic.log"
	listsDir    = "/etc/filter/lists"
)

var (
	whitelists = make(map[string]map[string]bool) // map[listName]map[ip]bool
	blacklists = make(map[string]map[string]bool)
	mutex      = &sync.RWMutex{}
	clients    = make(map[*websocket.Conn]bool)
	broadcast  = make(chan []byte)

	// Статистика за текущую секунду
	currentStats = struct {
		TotalBytes int64
		WLBytes    int64
		BLBytes    int64
		sync.Mutex
	}{}

	logFilePtr     *os.File
	trafficFilePtr *os.File
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Разрешаем все источники (для теста)
	},
}

func initLogs() {
	var err error
	logFilePtr, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Ошибка открытия лога: %v", err)
	}
	log.SetOutput(logFilePtr)

	trafficFilePtr, err = os.OpenFile(trafficFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Ошибка открытия traffic.log: %v", err)
	}

	// Создаём директорию для списков
	if err := os.MkdirAll(listsDir, 0755); err != nil {
		log.Fatalf("Ошибка создания директории для списков: %v", err)
	}
}

func saveLists() {
	mutex.Lock()
	defer mutex.Unlock()

	// Сохраняем whitelists
	for listName, list := range whitelists {
		fileName := filepath.Join(listsDir, fmt.Sprintf("%s_WL.txt", listName))
		file, err := os.Create(fileName)
		if err != nil {
			log.Printf("Ошибка сохранения whitelist %s: %v", listName, err)
			continue
		}
		defer file.Close()
		for ip := range list {
			fmt.Fprintf(file, "%s\n", ip)
		}
	}

	// Сохраняем blacklists
	for listName, list := range blacklists {
		fileName := filepath.Join(listsDir, fmt.Sprintf("%s_BL.txt", listName))
		file, err := os.Create(fileName)
		if err != nil {
			log.Printf("Ошибка сохранения blacklist %s: %v", listName, err)
			continue
		}
		defer file.Close()
		for ip := range list {
			fmt.Fprintf(file, "%s\n", ip)
		}
	}
}

func loadLists() {
	mutex.Lock()
	defer mutex.Unlock()
	whitelists = make(map[string]map[string]bool)
	blacklists = make(map[string]map[string]bool)

	// Читаем все файлы из директории
	files, err := os.ReadDir(listsDir)
	if err != nil {
		log.Printf("Ошибка чтения директории списков: %v", err)
		return
	}

	for _, file := range files {
		name := file.Name()
		if strings.HasSuffix(name, "_WL.txt") {
			listName := strings.TrimSuffix(name, "_WL.txt")
			whitelists[listName] = make(map[string]bool)
			f, err := os.Open(filepath.Join(listsDir, name))
			if err != nil {
				log.Printf("Ошибка открытия %s: %v", name, err)
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				ip := strings.TrimSpace(scanner.Text())
				if ip != "" {
					whitelists[listName][ip] = true
				}
			}
			f.Close()
		} else if strings.HasSuffix(name, "_BL.txt") {
			listName := strings.TrimSuffix(name, "_BL.txt")
			blacklists[listName] = make(map[string]bool)
			f, err := os.Open(filepath.Join(listsDir, name))
			if err != nil {
				log.Printf("Ошибка открытия %s: %v", name, err)
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				ip := strings.TrimSpace(scanner.Text())
				if ip != "" {
					blacklists[listName][ip] = true
				}
			}
			f.Close()
		}
	}
}

func saveTrafficStats() {
	for {
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))

		currentStats.Lock()
		total := currentStats.TotalBytes
		wl := currentStats.WLBytes
		bl := currentStats.BLBytes
		currentStats.TotalBytes = 0
		currentStats.WLBytes = 0
		currentStats.BLBytes = 0
		currentStats.Unlock()

		logEntry := fmt.Sprintf("%s total:%d wl:%d bl:%d\n",
			time.Now().Truncate(time.Second).Format(time.RFC3339), total, wl, bl)
		mutex.Lock()
		fmt.Fprint(trafficFilePtr, logEntry)
		trafficFilePtr.Sync()
		mutex.Unlock()

		// Отправляем данные через WebSocket
		broadcast <- []byte(fmt.Sprintf(`{"Incoming": %d, "Passed": %d, "Dropped": {"Blacklist": %d}}`, total, wl, bl))
	}
}

func handlePackets() {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Ошибка открытия интерфейса %s: %v", iface, err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		clientIP := ip.SrcIP.String()
		bytes := int64(len(packet.Data()))

		currentStats.Lock()
		currentStats.TotalBytes += bytes
		currentStats.Unlock()

		mutex.RLock()
		// Проверяем whitelists
		passed := false
		for listName, list := range whitelists {
			if listName == "default" && list[clientIP] {
				passed = true
				break
			}
		}
		if len(whitelists) > 0 && !passed {
			mutex.RUnlock()
			currentStats.Lock()
			currentStats.WLBytes += bytes
			currentStats.Unlock()
			continue
		}

		// Проверяем blacklists
		dropped := false
		for listName, list := range blacklists {
			if listName == "default" && list[clientIP] {
				dropped = true
				break
			}
		}
		if dropped {
			mutex.RUnlock()
			currentStats.Lock()
			currentStats.BLBytes += bytes
			currentStats.Unlock()
			continue
		}
		mutex.RUnlock()
	}
}

func wsHandler(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Ошибка WebSocket: %v", err)
		return
	}
	defer conn.Close()

	mutex.Lock()
	clients[conn] = true
	mutex.Unlock()

	for message := range broadcast {
		err := conn.WriteMessage(websocket.TextMessage, message)
		if err != nil {
			log.Printf("Ошибка отправки WebSocket: %v", err)
			mutex.Lock()
			delete(clients, conn)
			mutex.Unlock()
			break
		}
	}
}

func getTrafficData(c *gin.Context) {
	file, err := os.Open(trafficFile)
	if err != nil {
		c.JSON(500, gin.H{"error": "Не удалось открыть traffic.log"})
		return
	}
	defer file.Close()

	var entries []map[string]interface{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 4 {
			continue
		}
		timestamp := parts[0]
		totalStr := strings.TrimPrefix(parts[1], "total:")
		wlStr := strings.TrimPrefix(parts[2], "wl:")
		blStr := strings.TrimPrefix(parts[3], "bl:")
		total, _ := strconv.ParseInt(totalStr, 10, 64)
		wl, _ := strconv.ParseInt(wlStr, 10, 64)
		bl, _ := strconv.ParseInt(blStr, 10, 64)
		entries = append(entries, map[string]interface{}{
			"timestamp": timestamp,
			"total":     total,
			"wl":        wl,
			"bl":        bl,
		})
	}

	if len(entries) > 60 {
		entries = entries[len(entries)-60:]
	}

	c.JSON(200, entries)
}

func getLists(c *gin.Context) {
	mutex.RLock()
	defer mutex.RUnlock()
	c.JSON(200, gin.H{
		"whitelists": whitelists,
		"blacklists": blacklists,
	})
}

func manageList(c *gin.Context) {
	var req struct {
		IP       string `json:"ip"`
		ListType string `json:"listType"`
		ListName string `json:"listName"`
		Action   string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Ошибка парсинга JSON: %v", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	log.Printf("Получен запрос: IP=%s, ListType=%s, ListName=%s, Action=%s", req.IP, req.ListType, req.ListName, req.Action)

	mutex.Lock()
	defer mutex.Unlock()

	var targetLists map[string]map[string]bool
	if req.ListType == "whitelist" {
		targetLists = whitelists
	} else {
		targetLists = blacklists
	}

	if _, exists := targetLists[req.ListName]; !exists {
		targetLists[req.ListName] = make(map[string]bool)
	}

	targetList := targetLists[req.ListName]
	if req.Action == "add" {
		targetList[req.IP] = true
	} else if req.Action == "remove" {
		delete(targetList, req.IP)
	}

	// Сохраняем списки после изменения
	saveLists()

	c.JSON(200, gin.H{"message": "Успешно"})
}

func bulkManageList(c *gin.Context) {
	var req struct {
		ListType string `json:"listType"`
		ListName string `json:"listName"`
		Content  string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Ошибка парсинга JSON: %v", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	log.Printf("Получен запрос bulk: ListType=%s, ListName=%s, Content=%s", req.ListType, req.ListName, req.Content)

	mutex.Lock()
	defer mutex.Unlock()

	var targetLists map[string]map[string]bool
	if req.ListType == "whitelist" {
		targetLists = whitelists
	} else {
		targetLists = blacklists
	}

	if _, exists := targetLists[req.ListName]; !exists {
		targetLists[req.ListName] = make(map[string]bool)
	}

	targetList := targetLists[req.ListName]
	for ip := range targetList {
		delete(targetList, ip)
	}

	lines := strings.Split(req.Content, "\n")
	for _, line := range lines {
		ip := strings.TrimSpace(line)
		if ip != "" {
			targetList[ip] = true
		}
	}

	// Сохраняем списки после изменения
	saveLists()

	c.JSON(200, gin.H{"message": "Список обновлён"})
}

func createList(c *gin.Context) {
	var req struct {
		ListType string `json:"listType"`
		ListName string `json:"listName"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Ошибка парсинга JSON: %v", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	log.Printf("Создание списка: ListType=%s, ListName=%s", req.ListType, req.ListName)

	mutex.Lock()
	defer mutex.Unlock()

	var targetLists map[string]map[string]bool
	if req.ListType == "whitelist" {
		targetLists = whitelists
	} else {
		targetLists = blacklists
	}

	if _, exists := targetLists[req.ListName]; exists {
		c.JSON(400, gin.H{"error": "Список с таким именем уже существует"})
		return
	}

	targetLists[req.ListName] = make(map[string]bool)
	saveLists()

	c.JSON(200, gin.H{"message": "Список создан"})
}

func deleteList(c *gin.Context) {
	var req struct {
		ListType string `json:"listType"`
		ListName string `json:"listName"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Ошибка парсинга JSON: %v", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	log.Printf("Удаление списка: ListType=%s, ListName=%s", req.ListType, req.ListName)

	mutex.Lock()
	defer mutex.Unlock()

	var targetLists map[string]map[string]bool
	if req.ListType == "whitelist" {
		targetLists = whitelists
	} else {
		targetLists = blacklists
	}

	if _, exists := targetLists[req.ListName]; !exists {
		c.JSON(404, gin.H{"error": "Список не найден"})
		return
	}

	delete(targetLists, req.ListName)

	// Удаляем файл
	var suffix string
	if req.ListType == "whitelist" {
		suffix = "WL"
	} else {
		suffix = "BL"
	}
	fileName := filepath.Join(listsDir, fmt.Sprintf("%s_%s.txt", req.ListName, suffix))
	if err := os.Remove(fileName); err != nil {
		log.Printf("Ошибка удаления файла %s: %v", fileName, err)
	}

	c.JSON(200, gin.H{"message": "Список удалён"})
}

func main() {
	initLogs()
	loadLists()
	defer logFilePtr.Close()
	defer trafficFilePtr.Close()

	go saveTrafficStats()
	go handlePackets()

	r := gin.Default()
	r.GET("/traffic", getTrafficData)
	r.GET("/ws", wsHandler)
	r.GET("/api/lists", getLists)
	r.POST("/api/manage", manageList)
	r.POST("/api/bulk-manage", bulkManageList)
	r.POST("/api/create-list", createList)
	r.POST("/api/delete-list", deleteList)

	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}
