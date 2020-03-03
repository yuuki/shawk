package agent

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yuuki/transtracer/collector"
	"github.com/yuuki/transtracer/db"
)

// Start starts agent.
func Start(interval time.Duration, flushInterval time.Duration, db *db.DB) {
	go Watch(interval, db)

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigch
	log.Printf("Received %s gracefully shutdown...\n", sig)

	time.Sleep(3 * time.Second)
	log.Println("--> Closing db connection...")
	if err := db.Close(); err != nil {
		log.Println(err)
		return
	}
	log.Println("Closed db connection")
}

// Watch watches host flows for localhost.
func Watch(interval time.Duration, db *db.DB) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	errChan := make(chan error, 1)
	for {
		select {
		case err := <-errChan:
			if err != nil {
				log.Printf("%+v\n", err)
			}
		case <-ticker.C:
			go collectAndPostHostFlows(db, errChan)
		}
	}
}

// RunOnce runs agent once.
func RunOnce(db *db.DB) error {
	errChan := make(chan error, 1)
	collectAndPostHostFlows(db, errChan)
	return <-errChan
}

// collectAndPostHostFlows collect host flows and
// store it to the buffer store.
func collectAndPostHostFlows(db *db.DB, errChan chan error) {
	start := time.Now()
	flows, err := collector.CollectHostFlows()
	if err != nil {
		errChan <- err
		return
	}
	elapsed := time.Since(start)
	logtime := time.Now().Format("2006-01-02 15:04:05")
	for _, f := range flows {
		log.Printf("%s [collect] %s\n", logtime, f)
	}
	log.Printf("%s [elapsed] %s\n", logtime, elapsed)
}

// Flusher flushes data into the CMDB periodically.
func Flusher(interval time.Duration, db *db.DB) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	errChan := make(chan error, 1)
	for {
		select {
		case err := <-errChan:
			if err != nil {
				log.Printf("%+v\n", err)
			}
		case <-ticker.C:
			flush(db, errChan)
		}
	}
}

func flush(db *db.DB, errChan chan error) {
	// errChan <- db.InsertOrUpdateHostFlows(flows)
}
