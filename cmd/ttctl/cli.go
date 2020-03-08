package main

import (
	"flag"
	"fmt"
	"io"
	"net"

	"github.com/yuuki/transtracer/db"
	"github.com/yuuki/transtracer/logging"
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

var logger = logging.New("main")

// Run execute the main process.
// It returns exit code.
func (c *CLI) Run(args []string) int {
	logger.SetOutput(c.errStream)

	var (
		ver     bool
		credits bool

		createSchema bool
		dbuser       string
		dbpass       string
		dbhost       string
		dbport       string
		dbname       string
		ipv4         string
		depth        int
	)
	flags := flag.NewFlagSet("ttctl", flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.Usage = func() {
		fmt.Fprint(c.errStream, helpText)
	}
	flags.BoolVar(&createSchema, "create-schema", false, "")
	flags.StringVar(&ipv4, "ipv4", "", "")
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
			logger.Fatalf("%v", err)
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
		logger.Errorf("depth must be 0 < depth < %d, but specified %d\n", maxGraphDepth, depth)
		return exitCodeErr
	}

	if createSchema {
		return c.createSchema(dbopt)
	}

	if ipv4 != "" {
		return c.doIPv4(ipv4, depth, dbopt)
	}

	return exitCodeOK
}

func (c *CLI) createSchema(opt *db.Opt) int {
	logger.Infof("Connecting postgres ...")

	db, err := db.New(opt)
	if err != nil {
		logger.Errorf("postgres initialize error: %v", err)
		return exitCodeErr
	}

	logger.Infof("Creating postgres schema ...")
	if err := db.CreateSchema(); err != nil {
		logger.Errorf("postgres initialize error: %v", err)
		return exitCodeErr
	}
	return exitCodeOK
}

func (c *CLI) doIPv4(ipv4 string, depth int, opt *db.Opt) int {
	db, err := db.New(opt)
	if err != nil {
		logger.Errorf("postgres initialize error: %v", err)
		return exitCodeErr
	}
	addr := net.ParseIP(ipv4)

	// print thet flows of passive nodes
	pflows, err := db.FindPassiveFlows([]net.IP{addr})
	if err != nil {
		logger.Errorf("find active flows error: %v", err)
		return exitCodeErr
	}
	for _, flows := range pflows {
		pnode := flows[0].PassiveNode
		fmt.Fprintf(c.outStream,
			"%s:%d ('%s', pgid=%d)\n", pnode.IPAddr, pnode.Port, pnode.Pname, pnode.Pgid)

		c.printPassiveFlows(flows)
	}

	// print the flows of active nodes
	aflows, err := db.FindActiveFlows([]net.IP{addr})
	if err != nil {
		logger.Errorf("find active flows error: %v", err)
		return exitCodeErr
	}
	for _, flows := range aflows {
		anode := flows[0].ActiveNode
		fmt.Fprintf(c.outStream,
			"%s ('%s', pgid=%d)\n", anode.IPAddr, anode.Pname, anode.Pgid)

		c.printActiveFlows(flows)
	}

	return exitCodeOK
}

func (c *CLI) printPassiveFlows(flows []*db.Flow) {
	// No implementation of printing tree with depth > 1
	for _, flow := range flows {
		fmt.Fprintf(c.outStream, "└<-- %s\n", flow.ActiveNode)
	}
}

func (c *CLI) printActiveFlows(flows []*db.Flow) {
	// No implementation of printing tree with depth > 1
	for _, flow := range flows {
		fmt.Fprintf(c.outStream, "└--> %s\n", flow.PassiveNode)
	}
}

var helpText = `Usage: ttctl [options]

ttctl is a CLI controller for transtracer.

Options:
  --create-schema           create transtracer table schema for postgres
  --dbuser                  postgres user
  --dbpass                  postgres user password
  --dbhost                  postgres host
  --dbport                  postgres port
  --dbname                  postgres database name
  --ipv4               		print trees regarding the ipv4 address as a root node
  --version, -v	            print version
  --help, -h                print help
`
