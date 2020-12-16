package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/EspressoCake/nmapdb/nmap"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/godo.v2/glob"
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
			"Protocol" TEXT,
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

func insertHost(db *sql.DB, protocol string, host string, port int, service string, additional string, index int) {
	insertHostRecord := `INSERT INTO scan_results(HostIP, Protocol, Port, Service, Additional_ID) VALUES (?, ?, ?, ?, ?)`
	statement, err := db.Prepare(insertHostRecord)
	if err != nil {
		println("We have an error here...")
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(protocol, host, port, testString(service), testString(additional))
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func getXMLFiles() []*glob.FileAsset {
	files, _, err := glob.Glob([]string{"*.xml"})

	if err != nil {
		panic(err)
	}

	return files
}

func main() {
	log.Println("Checking for a database...")

	// Initial declaration due to scoping of if/else blocks
	var sqliteDatabase *sql.DB
	if _, err := os.Stat("./sqlite-database.db"); os.IsNotExist(err) {
		sqliteDatabase, _ = sql.Open("sqlite3", "./sqlite-database.db")
		defer sqliteDatabase.Close()

		fmt.Println("We're going to have to make a new database...starting now.")
		prepareTable(sqliteDatabase)
	} else {
		sqliteDatabase, _ = sql.Open("sqlite3", "./sqlite-database.db")
		defer sqliteDatabase.Close()
	}

	generalData := getXMLFiles()

	if generalData != nil {
		for _, value := range generalData {
			fmt.Println("Processing file: ", value.Path)
			content, err := ioutil.ReadFile(value.Path)
			if err != nil {
				log.Fatal(err)
			}
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
							insertHost(sqliteDatabase, ip.Addr, portInfo.Protocol, portInfo.PortId, portInfo.Service.Product, portInfo.Service.Version, index+1)
							generalIndex++
						}
					}
				}
			}
		}
	}

	fmt.Println("Ok, all done.")
}
