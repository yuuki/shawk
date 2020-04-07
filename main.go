package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/yuuki/shawk/command"
	"github.com/yuuki/shawk/logging"
	"github.com/yuuki/shawk/statik"
	"github.com/yuuki/shawk/version"
)

const (
	exitCodeOK  = 0
	exitCodeErr = 10 + iota
)

var (
	logger = logging.New("main")
)

// CLI is the command line object.
type CLI struct {
	// outStream and errStream are the stdout and stderr
	// to write message from the CLI.
	outStream, errStream io.Writer
}

func main() {
	cli := &CLI{outStream: os.Stdout, errStream: os.Stderr}
	os.Exit(cli.Run(os.Args))
}

// Run invokes the CLI with the given arguments.
func (c *CLI) Run(args []string) int {
	logging.SetOutput(c.errStream)

	if len(args) <= 1 {
		printHelp(c.errStream)
		return exitCodeErr
	}

	var err error

next:
	switch args[1] {
	case "look":
		err = c.doLook(args[2:])
	case "probe":
		err = c.doProbe(args[2:])
	case "create-scheme":
		err = c.doCreateScheme(args[2:])
	case "version", "--version":
		version.PrintVersion(c.errStream)
		return exitCodeOK
	case "help", "-h", "--help":
		printHelp(c.outStream)
		return exitCodeOK
	case "credits", "--credits":
		text, err := statik.FindString("/CREDITS")
		if err != nil {
			logger.Fatalf("%v", err)
		}
		fmt.Fprintln(c.outStream, text)
		return exitCodeOK
	case "--debug":
		logging.SetLogLevel(logging.DEBUG)
		args = args[1:]
		goto next
	default:
		printHelp(c.errStream)
		return exitCodeErr
	}

	if err != nil {
		fmt.Fprintf(c.errStream, "%+v\n", err)
		return exitCodeErr
	}

	return 0
}

var helpText = `Usage: shawk [options]

  A socket-based tracing system for discovering network dependencies in distributed applications.

Commands:
  look           show dependencies starting from a specified node.
  probe          start agent for collecting flows and processes.
  create-scheme  create CMDB scheme.

Options:
  --version         print version
  --credits         print credits
  --help, -h        print help
`

func printHelp(w io.Writer) {
	fmt.Fprint(w, helpText)
}

func (c *CLI) prepareFlags(help string) *flag.FlagSet {
	flags := flag.NewFlagSet("shawk", flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.Usage = func() {
		fmt.Fprint(c.errStream, help)
	}
	return flags
}

var lookHelpText = `
Usage: shawk look [options]

show dependencies starting from a specified node.

Options:
  --ipv4               		print trees regarding the ipv4 address as a root node
  --depth                   depth of dependency graph
  --dbuser                  postgres user
  --dbpass                  postgres user password
  --dbhost                  postgres host
  --dbport                  postgres port
  --dbname                  postgres database name
`

const defaultDepth = 1

func (c *CLI) doLook(args []string) error {
	var param command.LookParam
	flags := c.prepareFlags(lookHelpText)
	flags.StringVar(&param.IPv4, "ipv4", "", "")
	flags.IntVar(&param.Depth, "depth", defaultDepth, "")
	flags.StringVar(&param.DB.User, "dbuser", "", "")
	flags.StringVar(&param.DB.Password, "dbpass", "", "")
	flags.StringVar(&param.DB.Host, "dbhost", "", "")
	flags.StringVar(&param.DB.Port, "dbport", "", "")
	flags.StringVar(&param.DB.DBName, "dbname", "", "")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if param.Depth <= 0 || param.Depth > command.MaxGraphDepth {
		return fmt.Errorf("depth must be 0 < depth < %d, but specified %d",
			command.MaxGraphDepth, param.Depth)
	}
	return command.Look(&param)
}

var probeHelpText = `
Usage: shawk probe [options]

start agent for collecting flows and processes.

Options:
  --mode                    agent mode ('polling' or 'streaming'. default: 'polling')
  --once                    run once only if --mode='polling'
  --interval-sec            interval of scan connection stats (default: %d) only if --mode='polling'
  --flush-interval-sec      interval of flushing data into the CMDB (default: %d) only if --mode='polling'
  --dbuser                  postgres user
  --dbpass                  postgres user password
  --dbhost                  postgres host
  --dbport                  postgres port
  --dbname                  postgres database name
`

const (
	defaultMode             = command.PollingMode
	defaultIntervalSec      = 5
	defaultFlushIntervalSec = 30
)

func (c *CLI) doProbe(args []string) error {
	var param command.ProbeParam
	flags := c.prepareFlags(probeHelpText)
	flags.StringVar(&param.Mode, "mode", defaultMode, "")
	flags.IntVar(&param.IntervalSec, "interval-sec", defaultIntervalSec, "")
	flags.IntVar(&param.FlushIntervalSec, "flush-interval-sec", defaultFlushIntervalSec, "")
	flags.StringVar(&param.DB.User, "dbuser", "", "")
	flags.StringVar(&param.DB.Password, "dbpass", "", "")
	flags.StringVar(&param.DB.Host, "dbhost", "", "")
	flags.StringVar(&param.DB.Port, "dbport", "", "")
	flags.StringVar(&param.DB.DBName, "dbname", "", "")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if param.Mode != command.PollingMode &&
		param.Mode != command.StreamingMode {
		return fmt.Errorf("--mode option must be '%s' or '%s'",
			command.PollingMode, command.StreamingMode)
	}

	return command.Probe(&param)
}

var createSchemeHelpText = `
Usage: shawk create-scheme [options]

create CMDB scheme.

Options:
  --dbuser                  postgres user
  --dbpass                  postgres user password
  --dbhost                  postgres host
  --dbport                  postgres port
  --dbname                  postgres database name
`

func (c *CLI) doCreateScheme(args []string) error {
	var param command.CreateSchemeParam
	flags := c.prepareFlags(createSchemeHelpText)
	flags.StringVar(&param.DB.User, "dbuser", "", "")
	flags.StringVar(&param.DB.Password, "dbpass", "", "")
	flags.StringVar(&param.DB.Host, "dbhost", "", "")
	flags.StringVar(&param.DB.Port, "dbport", "", "")
	flags.StringVar(&param.DB.DBName, "dbname", "", "")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return command.CreateScheme(&param)
}
