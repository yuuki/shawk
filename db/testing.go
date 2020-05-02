package db

import (
	"context"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/ory/dockertest"
)

var (
	_, b, _, _ = runtime.Caller(0)
	root       = filepath.Join(filepath.Dir(b), "../")

	_, remainTestContainer = os.LookupEnv("SHAWK_TEST_REMAIN_CONTAINER")
)

// TestDB represents a database resource for testing.
type TestDB struct {
	pool     *dockertest.Pool
	resource *dockertest.Resource
	pgURL    *url.URL
}

// NewTestDB creates database instance for testing.
func NewTestDB() *TestDB {
	pgURL := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword("shawktest", "shawktest"),
		Path:   "shawktest",
	}
	q := pgURL.Query()
	q.Add("sslmode", "disable")
	pgURL.RawQuery = q.Encode()

	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not create new dockertest pool: %v", err)
	}

	// customizing postgres query logging conf for debugging
	path := filepath.Join(root, "/scripts/docker-entrypoint-initdb.d")
	runOpts := dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "11.7",
		Mounts:     []string{path + ":/docker-entrypoint-initdb.d"},
		Env: []string{
			"POSTGRES_USER=shawktest",
			"POSTGRES_PASSWORD=shawktest",
			"POSTGRES_DB=shawktest",
		},
	}

	resource, err := pool.RunWithOptions(&runOpts)
	if err != nil {
		log.Fatalf("Could start postgres container: %v", err)
	}
	pgURL.Host = resource.Container.NetworkSettings.IPAddress

	// Docker layer network is different on Mac
	if runtime.GOOS == "darwin" {
		pgURL.Host = net.JoinHostPort(resource.GetBoundIP("5432/tcp"), resource.GetPort("5432/tcp"))
	}

	pool.MaxWait = 10 * time.Second
	err = pool.Retry(func() error {
		ctx := context.Background()
		db, err := pgx.Connect(ctx, pgURL.String())
		if err != nil {
			return err
		}
		defer db.Close(ctx)
		return db.Ping(ctx)
	})
	if err != nil {
		log.Fatalf("Could not connect to postgres server: %v", err)
		if err := pool.Purge(resource); err != nil {
			log.Fatalf("Could not purge resource: %v", err)
		}
	}

	tdb := &TestDB{
		pool:     pool,
		resource: resource,
		pgURL:    pgURL,
	}
	return tdb
}

// GetURL returnes the URL for database endpoint.
func (tdb *TestDB) GetURL() *url.URL {
	return tdb.pgURL
}

// Purge purges the database
func (tdb *TestDB) Purge() {
	if remainTestContainer {
		return
	}

	err := tdb.pool.Purge(tdb.resource)
	if err != nil {
		log.Fatalf("Could not purge resource: %v", err)
	}
}
