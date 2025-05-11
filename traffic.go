package main

import (
	"database/sql"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/mattn/go-sqlite3"
)

const (
	dbFile = "/app/network.db"
)

var (
	currentStats = struct {
		TotalBytes int64
		WLBytes    int64
		BLBytes    int64
		sync.Mutex
	}{}
	db         *sql.DB
	iface      string
	whitelists map[string]*net.IPNet
	blacklists map[string]*net.IPNet
	mutex      sync.RWMutex
)

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatalf("Ошибка открытия базы данных: %v", err)
	}

	// Создание или проверка схемы таблиц
	sqlStmt := `
	CREATE TABLE IF NOT EXISTS traffic (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		interface TEXT,
		total_bytes INTEGER,
		wl_bytes INTEGER,
		bl_bytes INTEGER
	);
	CREATE TABLE IF NOT EXISTS lists (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		list_name TEXT,
		ip_cidr TEXT,
		list_type TEXT,
		enabled INTEGER DEFAULT 1
	);
	CREATE TABLE IF NOT EXISTS interfaces (
		name TEXT PRIMARY KEY,
		selected INTEGER DEFAULT 0
	);
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatalf("Ошибка создания таблиц: %v", err)
	}

	// Миграция: добавление колонки selected, если её нет
	_, err = db.Exec("ALTER TABLE interfaces ADD COLUMN IF NOT EXISTS selected INTEGER DEFAULT 0")
	if err != nil {
		log.Printf("Ошибка миграции таблицы interfaces: %v", err)
	}
}

func getSelectedInterface() string {
	var selectedInterface string
	for {
		row := db.QueryRow("SELECT name FROM interfaces WHERE selected = 1 LIMIT 1")
		err := row.Scan(&selectedInterface)
		if err == sql.ErrNoRows {
			log.Println("Интерфейс не выбран, ожидаем...")
			time.Sleep(5 * time.Second)
			continue
		} else if err != nil {
			log.Printf("Ошибка получения интерфейса: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		// Проверяем, доступен ли интерфейс для захвата
		_, err = pcap.OpenLive(selectedInterface, 1600, true, pcap.BlockForever)
		if err != nil {
			log.Printf("Интерфейс %s недоступен для захвата: %v", selectedInterface, err)
			// Сбрасываем выбор интерфейса
			db.Exec("UPDATE interfaces SET selected = 0 WHERE name = ?", selectedInterface)
			// Исключаем виртуальные интерфейсы (например, veth*)
			if strings.HasPrefix(selectedInterface, "veth") {
				log.Printf("Пропуск виртуального интерфейса %s", selectedInterface)
				continue
			}
			time.Sleep(5 * time.Second)
			continue
		}
		return selectedInterface
	}
}

func loadLists() {
	mutex.Lock()
	defer mutex.Unlock()
	whitelists = make(map[string]*net.IPNet)
	blacklists = make(map[string]*net.IPNet)

	rows, err := db.Query("SELECT ip_cidr, list_type FROM lists WHERE enabled = 1")
	if err != nil {
		log.Printf("Ошибка загрузки списков: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var ipCidr, listType string
		if err := rows.Scan(&ipCidr, &listType); err != nil {
			log.Printf("Ошибка сканирования списков: %v", err)
			continue
		}
		_, ipNet, err := net.ParseCIDR(ipCidr)
		if err != nil {
			log.Printf("Ошибка парсинга CIDR %s: %v", ipCidr, err)
			continue
		}
		if listType == "whitelist" {
			whitelists[ipCidr] = ipNet
		} else {
			blacklists[ipCidr] = ipNet
		}
	}
}

func saveTrafficStats(interfaceName string) {
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

		_, err := db.Exec("INSERT INTO traffic (interface, total_bytes, wl_bytes, bl_bytes) VALUES (?, ?, ?, ?)",
			interfaceName, total, wl, bl)
		if err != nil {
			log.Printf("Ошибка записи в базу данных: %v", err)
		}
	}
}

func handlePackets(interfaceName string) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Ошибка открытия интерфейса %s: %v", interfaceName, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		bytes := int64(len(packet.Data()))

		currentStats.Lock()
		currentStats.TotalBytes += bytes
		currentStats.Unlock()

		mutex.RLock()
		passed := false
		for _, ipNet := range whitelists {
			if ipNet.Contains(ip.SrcIP) {
				passed = true
				break
			}
		}
		if !passed {
			mutex.RUnlock()
			currentStats.Lock()
			currentStats.WLBytes += bytes
			currentStats.Unlock()
			continue
		}

		dropped := false
		for _, ipNet := range blacklists {
			if ipNet.Contains(ip.SrcIP) {
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

func main() {
	log.Println("Запуск traffic-collector...")
	initDB()
	defer db.Close()

	for {
		iface = getSelectedInterface()
		log.Printf("Запуск сбора трафика на интерфейсе: %s", iface)

		// Перезагружаем списки перед началом обработки
		loadLists()

		// Запускаем обработку пакетов в горутине
		go saveTrafficStats(iface)
		go handlePackets(iface)

		// Проверяем, не изменился ли интерфейс
		for {
			time.Sleep(10 * time.Second)
			newIface := getSelectedInterface()
			if newIface != iface {
				log.Printf("Интерфейс изменён на %s, перезапуск...", newIface)
				break
			}
		}
	}
}
