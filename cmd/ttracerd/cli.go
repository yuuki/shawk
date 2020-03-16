package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/yuuki/transtracer/agent"
	"github.com/yuuki/transtracer/db"
	"github.com/yuuki/transtracer/logging"
	"github.com/yuuki/transtracer/statik"
	"github.com/yuuki/transtracer/version"
)

const (
	exitCodeOK  = 0
	exitCodeErr = 10 + iota

	defaultMode             = agent.POLLING_MODE
	defaultIntervalSec      = 5
	defaultFlushIntervalSec = 30
)

var logger = logging.New("main")

// CLI is the command line object.
type CLI struct {
	// outStream and errStream are the stdout and stderr
	// to write message from the CLI.
	outStream, errStream io.Writer
}

// Run execute the main process.
// It returns exit code.
func (c *CLI) Run(args []string) int {
	logging.SetOutput(c.errStream)

	var (
		ver     bool
		credits bool
		debug   bool

		mode             string
		once             bool
		dbuser           string
		dbpass           string
		dbhost           string
		dbport           string
		dbname           string
		intervalSec      int
		flushIntervalSec int
	)
	flags := flag.NewFlagSet("ttracerd", flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.Usage = func() { printHelp(c.errStream) }
	flags.StringVar(&mode, "mode", defaultMode, "")
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
			logger.Fatalf("%v", err)
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
		logger.Errorf("postgres initialize error: %v", err)
		return exitCodeErr
	}
	logger.Infof("Connected postgres")

	switch mode {
	case agent.PollingMode:
		if once {
			if err := agent.RunOnce(db); err != nil {
				logger.Errorf("%+v", err)
				return exitCodeErr
			}
		} else {
			err := agent.Start(time.Duration(intervalSec)*time.Second,
				time.Duration(flushIntervalSec)*time.Second, db)
			if err != nil {
				logger.Errorf("%+v", err)
				return exitCodeErr
			}
		}
	case agent.StreamingMode:
		err := agent.StartWithStreaming(db)
		if err != nil {
			logger.Errorf("%+v", err)
			return exitCodeErr
		}
	default:
		fmt.Fprintf(c.errStream, "The value of --mode option must be '%s' or '%s'\n", agent.PollingMode, agent.StreamingMode)
		printHelp(c.errStream)
		return exitCodeErr
	}

	return exitCodeOK
}

var helpText = fmt.Sprintf(`Usage: ttracerd [options]

An agent process for collecting flows and processes.

Options:
  --mode                    agent mode ('polling' or 'streaming'. default: 'polling')
  --once                    run once only if --mode='polling'
  --dbuser                  postgres user
  --dbpass                  postgres user password
  --dbhost                  postgres host
  --dbport                  postgres port
  --dbname                  postgres database name
  --interval-sec            interval of scan connection stats (default: %d) only if --mode='polling'
  --flush-interval-sec      interval of flushing data into the CMDB (default: %d) only if --mode='polling'
  --debug                   run with debug information

  --credits                 print credits
  --version, -v	            print version
  --help, -h                print help
`, defaultIntervalSec, defaultFlushIntervalSec)

func printHelp(w io.Writer) {
	fmt.Fprint(w, helpText)
}
