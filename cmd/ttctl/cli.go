package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/yuuki/transtracer/db"
	"github.com/yuuki/transtracer/statik"
	"github.com/yuuki/transtracer/version"
)

const (
	exitCodeOK    = 0
	exitCodeErr   = 10 + iota
	maxGraphDepth = 4
)

// CLI is the command line object.
type CLI struct {
	// outStream and errStream are the stdout and stderr
	// to write message from the CLI.
	outStream, errStream io.Writer
}

// Run execute the main process.
// It returns exit code.
func (c *CLI) Run(args []string) int {
	log.SetOutput(c.errStream)

	var (
		ver     bool
		credits bool

		createSchema bool
		dbuser       string
		dbpass       string
		dbhost       string
		dbport       string
		dbname       string
		destipv4     string
		depth        int
	)
	flags := flag.NewFlagSet("mftctl", flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.Usage = func() {
		fmt.Fprint(c.errStream, helpText)
	}
	flags.BoolVar(&createSchema, "create-schema", false, "")
	flags.StringVar(&destipv4, "dest-ipv4", "", "")
	flags.StringVar(&dbuser, "dbuser", "", "")
	flags.StringVar(&dbpass, "dbpass", "", "")
	flags.StringVar(&dbhost, "dbhost", "", "")
	flags.StringVar(&dbport, "dbport", "", "")
	flags.StringVar(&dbname, "dbname", "", "")
	flags.IntVar(&depth, "depth", maxGraphDepth, "")
	flags.BoolVar(&ver, "version", false, "")
	flags.BoolVar(&credits, "credits", false, "")
	if err := flags.Parse(args[1:]); err != nil {
		return exitCodeErr
	}

	if ver {
		version.PrintVersion(c.errStream)
		return exitCodeOK
	}

	if credits {
		text, err := statik.FindString("CREDITS")
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Fprintln(c.outStream, text)
		return exitCodeOK
	}

	dbopt := &db.Opt{
		DBName:   dbname,
		User:     dbuser,
		Password: dbpass,
		Host:     dbhost,
		Port:     dbport,
	}

	if depth <= 0 || depth > maxGraphDepth {
		log.Printf("depth must be 0 < depth < %d, but specified %d\n", maxGraphDepth, depth)
		return exitCodeErr
	}

	if createSchema {
		return c.createSchema(dbopt)
	}

	if destipv4 != "" {
		return c.destIPv4(destipv4, depth, dbopt)
	}

	return exitCodeOK
}

func (c *CLI) createSchema(opt *db.Opt) int {
	log.Println("Connecting postgres ...")

	db, err := db.New(opt)
	if err != nil {
		log.Printf("postgres initialize error: %v\n", err)
		return exitCodeErr
	}

	log.Println("Creating postgres schema ...")
	if err := db.CreateSchema(); err != nil {
		log.Printf("postgres initialize error: %v\n", err)
		return exitCodeErr
	}
	return exitCodeOK
}

func (c *CLI) destIPv4(ipv4 string, depth int, opt *db.Opt) int {
	db, err := db.New(opt)
	if err != nil {
		log.Printf("postgres initialize error: %v\n", err)
		return exitCodeErr
	}
	addr := net.ParseIP(ipv4)
	portsbyaddr, err := db.FindListeningPortsByAddrs([]net.IP{addr})
	if err != nil {
		log.Println(err)
		return exitCodeErr
	}
	for _, addrports := range portsbyaddr {
		for _, addrport := range addrports {
			fmt.Fprintf(c.outStream, "%s:%d ('%s', pgid=%d)\n", addrport.IPAddr, addrport.Port, addrport.Pname, addrport.Pgid)
			if err := c.printDestIPv4(db, addrport, 1, depth); err != nil {
				return exitCodeErr
			}
		}
	}
	return exitCodeOK
}

func (c *CLI) printDestIPv4(db *db.DB, addrport *db.AddrPort, curDepth, depth int) error {
	addrports, err := db.FindSourceByDestAddrAndPort(addrport.IPAddr, addrport.Port)
	if err != nil {
		return err
	}
	if len(addrports) == 0 {
		return nil
	}
	indent := strings.Repeat("\t", curDepth-1)
	curDepth++
	depth--
	for _, addrport := range addrports {
		fmt.Fprint(c.outStream, indent)
		fmt.Fprint(c.outStream, "└<-- ")
		fmt.Fprint(c.outStream, addrport)
		fmt.Fprintln(c.outStream)
		if err := c.printDestIPv4(db, addrport, curDepth, depth); err != nil {
			return err
		}
	}
	return nil
}

var helpText = `Usage: ttctl [options]

ttctl is a CLI controller for mftracer system.

Options:
  --create-schema           create mftracer table schema for postgres
  --dbuser                  postgres user
  --dbpass                  postgres user password
  --dbhost                  postgres host
  --dbport                  postgres port
  --dbname                  postgres database name
  --dest-ipv4               filter by destination ipv4 address
  --version, -v	            print version
  --help, -h                print help
`
