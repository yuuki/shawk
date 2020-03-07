package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/mackerelio/golib/logging"
	"github.com/yuuki/transtracer/agent"
	"github.com/yuuki/transtracer/db"
	"github.com/yuuki/transtracer/statik"
	"github.com/yuuki/transtracer/version"
)

const (
	exitCodeOK              = 0
	exitCodeErr             = 10 + iota
	defaultIntervalSec      = 5
	defaultFlushIntervalSec = 30
)

var logger = logging.GetLogger("main")

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
		debug   bool

		once             bool
		dbuser           string
		dbpass           string
		dbhost           string
		dbport           string
		dbname           string
		intervalSec      int
		flushIntervalSec int
	)
	flags := flag.NewFlagSet("transtracerd", flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.Usage = func() {
		fmt.Fprint(c.errStream, helpText)
	}
	flags.BoolVar(&once, "once", false, "")
	flags.StringVar(&dbuser, "dbuser", "", "")
	flags.StringVar(&dbpass, "dbpass", "", "")
	flags.StringVar(&dbhost, "dbhost", "", "")
	flags.StringVar(&dbport, "dbport", "", "")
	flags.StringVar(&dbname, "dbname", "", "")
	flags.IntVar(&intervalSec, "interval-sec", defaultIntervalSec, "")
	flags.IntVar(&flushIntervalSec, "flush-interval-sec", defaultFlushIntervalSec, "")
	flags.BoolVar(&ver, "version", false, "")
	flags.BoolVar(&credits, "credits", false, "")
	flags.BoolVar(&debug, "debug", false, "")
	if err := flags.Parse(args[1:]); err != nil {
		return exitCodeErr
	}

	if ver {
		version.PrintVersion(c.errStream)
		return exitCodeOK
	}

	if credits {
		text, err := statik.FindString("/CREDITS")
		if err != nil {
			logger.Criticalf("%v", err)
		}
		fmt.Fprintln(c.outStream, text)
		return exitCodeOK
	}

	if debug {
		logging.SetLogLevel(logging.DEBUG)
	}

	logger.Infof("--> Connecting postgres ...")
	db, err := db.New(&db.Opt{
		DBName:   dbname,
		User:     dbuser,
		Password: dbpass,
		Host:     dbhost,
		Port:     dbport,
	})
	if err != nil {
		logger.Infof("postgres initialize error: %v", err)
		return exitCodeErr
	}
	logger.Infof("Connected postgres")

	if once {
		if err := agent.RunOnce(db); err != nil {
			log.Printf("%+v\n", err)
			return exitCodeErr
		}
	} else {
		agent.Start(time.Duration(intervalSec)*time.Second,
			time.Duration(flushIntervalSec)*time.Second, db)
	}

	return exitCodeOK
}

var helpText = fmt.Sprintf(`Usage: ttracerd [options]

An agent process for collecting flows and processes.

Options:
  --once                    run once
  --dbuser                  postgres user
  --dbpass                  postgres user password
  --dbhost                  postgres host
  --dbport                  postgres port
  --dbname                  postgres database name
  --interval-sec            interval of scan connection stats (default: %d)
  --flush-interval-sec      interval of flushing data into the CMDB (default: %d)
  --debug                   run with debug information
  --credits                 print credits
  --version, -v	            print version
  --help, -h                print help
`, defaultIntervalSec, defaultFlushIntervalSec)
