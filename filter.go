package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
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
)

var (
	whitelist = make(map[string]bool)
	blacklist = make(map[string]bool)
	mutex     = &sync.RWMutex{}
	clients   = make(map[*websocket.Conn]bool)
	broadcast = make(chan []byte)

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
}

func loadLists() {
	mutex.Lock()
	defer mutex.Unlock()
	whitelist = make(map[string]bool)
	blacklist = make(map[string]bool)

	if file, err := os.Open("/etc/filter/whitelist.txt"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				whitelist[ip] = true
			}
		}
	}

	if file, err := os.Open("/etc/filter/blacklist.txt"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				blacklist[ip] = true
			}
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
		if len(whitelist) > 0 && !whitelist[clientIP] {
			mutex.RUnlock()
			currentStats.Lock()
			currentStats.WLBytes += bytes
			currentStats.Unlock()
			continue
		}
		mutex.RUnlock()

		mutex.RLock()
		if blacklist[clientIP] {
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

	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}
