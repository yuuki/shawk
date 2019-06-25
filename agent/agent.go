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
func Start(interval time.Duration, db *db.DB) {
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
func Watch(interval time.Duration, db *db.DB) error {
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
	return nil
}

// RunOnce runs agent once.
func RunOnce(db *db.DB) error {
	errChan := make(chan error, 1)
	collectAndPostHostFlows(db, errChan)
	return <-errChan
}

// collectAndPostHostFlows collect host flows and
// post it to the data store.
func collectAndPostHostFlows(db *db.DB, errChan chan error) {
	flows, err := collector.CollectHostFlows()
	if err != nil {
		errChan <- err
		return
	}
	errChan <- db.InsertOrUpdateHostFlows(flows)
	log.Printf("Post host flows (%d)", len(flows))
}
