package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/joho/godotenv"

	"github.com/yuuki/shawk/command"
	"github.com/yuuki/shawk/config"
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

	if env := os.Getenv("SHAWK_ENV_FILE"); env != "" {
		if err := godotenv.Load(env); err != nil {
			log.Fatalf("Cannot start load config from env: %v\n", err)
		}
	}

	if err := config.Load(); err != nil {
		log.Fatalf("Cannot load config from env: %v\n", err)
	}

	var (
		debug bool
		help  bool
	)
	flags := flag.NewFlagSet("shawk", flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.Usage = func() {
		printHelp(c.errStream)
	}
	flags.BoolVar(&help, "help", false, "")
	flags.BoolVar(&debug, "debug", false, "")
	if err := flags.Parse(args[1:]); err != nil {
		return exitCodeErr
	}

	if help {
		printHelp(c.outStream)
		return exitCodeOK
	}

	if debug {
		logging.SetLogLevel(logging.DEBUG)
	}

	var err error
	switch args[1] {
	case "look":
		err = c.doLook(args[2:])
	case "probe":
		err = c.doProbe(args[2:])
	case "create-scheme":
		err = c.doCreateScheme(args[2:])
	case "version":
		version.PrintVersion(c.errStream)
		return exitCodeOK
	case "credits":
		text, err := statik.FindString("/CREDITS")
		if err != nil {
			logger.Fatalf("%v", err)
		}
		fmt.Fprintln(c.outStream, text)
		return exitCodeOK
	case "help":
		printHelp(c.outStream)
		return exitCodeOK
	default:
		fmt.Fprintf(c.errStream, "No such sub command: %s\n", args[1])
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

  version        print version
  credits        print credits
  help           print help

Options:
  --help         print help
  --debug        enable debug logging

Environs:
  SHAWK_ENV_FILE=/path/to/envfile
`

func printHelp(w io.Writer) {
	fmt.Fprint(w, helpText)
}

func (c *CLI) prepareFlags(name, help string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(c.errStream)
	flags.Usage = func() {
		fmt.Fprint(c.errStream, help)
	}
	return flags
}

var lookHelpText = `
Usage: shawk look [options]

print dependencies starting from a specified node.

Options:
  --ipv4 ADDR              	filter flows regarding a specific ipv4 address as a root node
  --since                   filter flows since a specific date (relative duration such as '5m', '2h45m')
  --until                   filter flows until a specific date (relative duration such as '5m', '2h45m')
  --depth                   depth of dependency graph
`

const defaultDepth = 1

func (c *CLI) doLook(args []string) error {
	var param command.LookParam
	flags := c.prepareFlags("look", lookHelpText)
	flags.StringVar(&param.IPv4, "ipv4", "", "")
	flags.StringVar(&param.Since, "since", "", "")
	flags.StringVar(&param.Until, "until", "", "")
	flags.IntVar(&param.Depth, "depth", defaultDepth, "")
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
  --env
  --once                    run once only if --mode='polling'
`

func (c *CLI) doProbe(args []string) error {
	var param command.ProbeParam
	flags := c.prepareFlags("probe", probeHelpText)
	flags.BoolVar(&param.Once, "once", false, "")
	if err := flags.Parse(args); err != nil {
		return err
	}

	return command.Probe(&param)
}

var createSchemeHelpText = `
Usage: shawk create-scheme [options]

create CMDB scheme.
`

func (c *CLI) doCreateScheme(args []string) error {
	var param command.CreateSchemeParam
	flags := c.prepareFlags("create-scheme", createSchemeHelpText)
	if err := flags.Parse(args); err != nil {
		return err
	}
	return command.CreateScheme(&param)
}
