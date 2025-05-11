package main

import (
	"database/sql"
	"log"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	dbPath = "/app/filter.db"
)

var (
	mutex        = &sync.RWMutex{}
	currentStats = struct {
		TotalBytes   int64
		PassedBytes  int64
		DroppedBytes int64
		sync.Mutex
	}{}
)

func loadRules(db *sql.DB) (map[string]bool, map[string]bool, map[string]struct {
	Interfaces []string
	IPs        map[string]bool
	Threshold  int64
	FilterActive bool
	Template   string
}) {
	whitelists := make(map[string]bool)
	blacklists := make(map[string]bool)
	monitoringObjects := make(map[string]struct {
		Interfaces []string
		IPs        map[string]bool
		Threshold  int64
		FilterActive bool
		Template   string
	})

	rows, err := db.Query("SELECT ip, list_type FROM rules WHERE list_type IN ('whitelist', 'blacklist')")
	if err != nil {
		log.Printf("Ошибка загрузки списков: %v", err)
		return whitelists, blacklists, monitoringObjects
	}
	defer rows.Close()
	for rows.Next() {
		var ip, listType string
		if err := rows.Scan(&ip, &listType); err != nil {
			log.Printf("Ошибка сканирования строки: %v", err)
			continue
		}
		if listType == "whitelist" {
			whitelists[ip] = true
		} else if listType == "blacklist" {
			blacklists[ip] = true
		}
	}

	rows, err = db.Query("SELECT name, interfaces, ips, threshold, filter_active, template FROM monitoring")
	if err != nil {
		log.Printf("Ошибка загрузки объектов мониторинга: %v", err)
		return whitelists, blacklists, monitoringObjects
	}
	defer rows.Close()
	for rows.Next() {
		var name, interfacesStr, ipsStr, template string
		var threshold int64
		var filterActive bool
		if err := rows.Scan(&name, &interfacesStr, &ipsStr, &threshold, &filterActive, &template); err != nil {
			log.Printf("Ошибка сканирования объекта мониторинга: %v", err)
			continue
		}
		interfaces := strings.Split(interfacesStr, ",")
		ips := make(map[string]bool)
		for _, ip := range strings.Split(ipsStr, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips[ip] = true
			}
		}
		monitoringObjects[name] = struct {
			Interfaces []string
			IPs        map[string]bool
			Threshold  int64
			FilterActive bool
			Template   string
		}{
			Interfaces:   interfaces,
			IPs:          ips,
			Threshold:    threshold,
			FilterActive: filterActive,
			Template:     template,
		}
	}
	log.Printf("Загружены правила: whitelists=%v, blacklists=%v, monitoringObjects=%v", whitelists, blacklists, monitoringObjects)
	return whitelists, blacklists, monitoringObjects
}

func handlePackets(db *sql.DB) {
	var handles []*pcap.Handle
	defer func() {
		for _, handle := range handles {
			handle.Close()
		}
	}()

	for {
		whitelists, blacklists, monitoringObjects := loadRules(db)

		interfaceSet := make(map[string]bool)
		for _, obj := range monitoringObjects {
			for _, iface := range obj.Interfaces {
				interfaceSet[iface] = true
			}
		}
		log.Printf("Обнаружены интерфейсы для мониторинга: %v", interfaceSet)

		for _, handle := range handles {
			handle.Close()
		}
		handles = nil

		for iface := range interfaceSet {
			handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
			if err != nil {
				log.Printf("Ошибка открытия интерфейса %s: %v", iface, err)
				continue
			}
			handles = append(handles, handle)
			log.Printf("Запущен мониторинг интерфейса: %s", iface)
			go func(h *pcap.Handle, iface string) {
				packetSource := gopacket.NewPacketSource(h, h.LinkType())
				for packet := range packetSource.Packets() {
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					if ipLayer == nil {
						continue
					}
					ip, _ := ipLayer.(*layers.IPv4)
					clientIP := ip.SrcIP.String()
					bytes := int64(len(packet.Data()))
					log.Printf("Получен пакет на интерфейсе %s: IP=%s, размер=%d байт", iface, clientIP, bytes)

					currentStats.Lock()
					currentStats.TotalBytes += bytes
					currentStats.Unlock()

					mutex.RLock()
					passed := whitelists[clientIP]
					if !passed && !blacklists[clientIP] {
						currentStats.Lock()
						currentStats.PassedBytes += bytes
						currentStats.Unlock()
						log.Printf("Пакет пропущен (не в списках): IP=%s, размер=%d байт", clientIP, bytes)
					}

					dropped := blacklists[clientIP]
					if dropped {
						currentStats.Lock()
						currentStats.DroppedBytes += bytes
						currentStats.Unlock()
						log.Printf("Пакет отклонён (blacklist): IP=%s, размер=%d байт", clientIP, bytes)
					}

					for _, obj := range monitoringObjects {
						if obj.FilterActive {
							for ip := range obj.IPs {
								if clientIP == ip {
									currentStats.Lock()
									currentStats.PassedBytes += bytes
									currentStats.Unlock()
									log.Printf("Пакет пропущен (объект мониторинга %s): IP=%s, размер=%d байт", obj, clientIP, bytes)
									break
								}
							}
						}
					}
					mutex.RUnlock()
				}
			}(handle, iface)
		}

		time.Sleep(10 * time.Second)
	}
}

func saveStats(db *sql.DB) {
	for {
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
		currentStats.Lock()
		total := currentStats.TotalBytes
		passed := currentStats.PassedBytes
		dropped := currentStats.DroppedBytes
		currentStats.TotalBytes = 0
		currentStats.PassedBytes = 0
		currentStats.DroppedBytes = 0
		currentStats.Unlock()

		log.Printf("Сохранение статистики: total=%d, passed=%d, dropped=%d", total, passed, dropped)
		_, err := db.Exec("INSERT INTO stats (timestamp, total, passed, dropped) VALUES (?, ?, ?, ?)",
			time.Now().Truncate(time.Second).Format(time.RFC3339), total, passed, dropped)
		if err != nil {
			log.Printf("Ошибка записи статистики: %v", err)
		}
	}
}

func initDB() *sql.DB {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Ошибка открытия БД: %v", err)
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, list_type TEXT)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS monitoring (name TEXT PRIMARY KEY, interfaces TEXT, ips TEXT, threshold INTEGER, filter_active BOOLEAN, template TEXT)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, total INTEGER, passed INTEGER, dropped INTEGER)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS interfaces (name TEXT PRIMARY KEY, type TEXT)`)
	return db
}

func main() {
	db := initDB()
	defer db.Close()

	go saveStats(db)
	go handlePackets(db)

	select {}
}
