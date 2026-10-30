// Command shawk discovers network dependencies among processes with eBPF.
package main

import (
	"os"

	"github.com/yuuki/shawk/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
