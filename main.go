package main

import (
	"database/sql"
	"io/ioutil"
	"log"
	"os"

	"github.com/EspressoCake/nmapdb/nmap"
	_ "github.com/mattn/go-sqlite3"
)

func testString(data string) string {
	if data != "" {
		return data
	}

	return "N/A"
}

func generateDB() {
	file, err := os.Create("sqlite-database.db")
	if err != nil {
		log.Fatal(err.Error())
	}

	file.Close()
}

func prepareTable(db *sql.DB) {
	createScanTable := `CREATE TABLE scan_results (
			"ID" integer NOT NULL PRIMARY KEY AUTOINCREMENT,		
			"HostIP" TEXT,
			"Port" INTEGER,
			"Service" TEXT,
			"Additional_ID" TEXT);`

	log.Println("Creating table...")
	statement, err := db.Prepare(createScanTable)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec()
	log.Println("Table created...")
}

func insertHost(db *sql.DB, host string, port int, service string, additional string, index int) {
	insertHostRecord := `INSERT INTO scan_results(HostIP, Port, Service, Additional_ID) VALUES (?, ?, ?, ?)`
	statement, err := db.Prepare(insertHostRecord)
	if err != nil {
		println("WE have an error here...")
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(host, port, testString(service), testString(additional))
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func main() {
	if argument := os.Args; len(argument) != 2 {
		os.Exit(1)
	}

	content, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Creating our database...")
	sqliteDatabase, _ := sql.Open("sqlite3", "./sqlite-database.db")
	defer sqliteDatabase.Close()

	prepareTable(sqliteDatabase)

	generalIndex := 1

	xmlContent, err := nmap.Parse(content)
	if err != nil {
		log.Fatal(err)
	} else {
		for _, item := range xmlContent.Hosts {
			for _, ip := range item.Addresses {
				for index, portInfo := range item.Ports {
					if generalIndex%1000 == 0 {
						log.Printf("Index: %d records written\n", generalIndex)
					}
					insertHost(sqliteDatabase, ip.Addr, portInfo.PortId, portInfo.Service.Product, portInfo.Service.Version, index+1)
					generalIndex++
				}
			}
		}
	}
}
