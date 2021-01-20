package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"

	"github.com/EspressoCake/nmapdb/nmap"
	"github.com/fatih/color"
	_ "github.com/mattn/go-sqlite3"
	"github.com/schollz/sqlite3dump"
	"gopkg.in/godo.v2/glob"
)

func testString(data string) string {
	if data != "" {
		return data
	}

	return "N/A"
}

func prepareTable(db *sql.DB) {
	createScanTable := `CREATE TABLE scan_results (
			"ID" integer NOT NULL PRIMARY KEY AUTOINCREMENT,		
			"HostIP" TEXT,
			"Protocol" TEXT,
			"Port" INTEGER,
			"State" TEXT,
			"Service" TEXT,
			"Additional_ID" TEXT);`

	log.Println("Creating table(s).")
	statement, err := db.Prepare(createScanTable)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec()
	log.Println("Table(s) created.")
}

func insertHost(db *sql.DB, protocol string, host string, status string, port int, service string, additional string, index int) {
	insertHostRecord := `INSERT INTO scan_results(HostIP, Protocol, Port, State, Service, Additional_ID) VALUES (?, ?, ?, ?, ?, ?)`
	statement, err := db.Prepare(insertHostRecord)
	if err != nil {
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(protocol, host, port, status, testString(service), testString(additional))
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

func dumpDatabase(databasePointer *sql.DB) {
	file, err := os.Create("sample.dmp")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	buffObject := bufio.NewWriter(file)
	err = sqlite3dump.DumpDB(databasePointer, buffObject)
	buffObject.Flush()

	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\n")
	} else {
		color.Cyan("sqlite3 newdb.db < sample.dmp")
	}
}

func generateXMLSlice() []*nmap.NmapRun {
	return make([]*nmap.NmapRun, len(getXMLFiles()))
}

func main() {
	sqliteDatabase, _ := sql.Open("sqlite3", ":memory:")
	defer sqliteDatabase.Close()
	prepareTable(sqliteDatabase)

	generalData := getXMLFiles()
	xmlDataStream := generateXMLSlice()

	// General debugging information
	fmt.Println("Number of files to ingest:", len(xmlDataStream))

	var wg sync.WaitGroup
	wg.Add(len(xmlDataStream))
	for i := 0; i < len(xmlDataStream); i++ {
		go func(i int) {
			defer wg.Done()

			content, err := ioutil.ReadFile(generalData[i].Path)
			if err != nil {

			} else {
				xmlContent, err := nmap.Parse(content)
				if err != nil {
				} else {
					xmlDataStream[i] = xmlContent
				}
			}
		}(i)
	}
	wg.Wait()

	for index, value := range xmlDataStream {
		if xmlDataStream[index] != nil {
			for _, host := range value.Hosts {
				for _, ip := range host.Addresses {
					for currentIndex, ports := range host.Ports {
						insertHost(sqliteDatabase, ip.Addr, ports.Protocol, ports.State.State, ports.PortId, ports.Service.Product, ports.Service.Version, currentIndex+1)
					}
				}
			}
		}
	}

	dumpDatabase(sqliteDatabase)
}

