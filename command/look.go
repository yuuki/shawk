package command

import (
	"fmt"
	"net"

	"github.com/yuuki/shawk/db"
	"golang.org/x/xerrors"
)

const (
	// MaxGraphDepth is maximum depth of dependency graph.
	MaxGraphDepth = 4
)

// LookParam represents a look command parameter.
type LookParam struct {
	IPv4  string
	Depth int
	DB    db.Opt
}

// Look runs look subcommand.
func Look(param *LookParam) error {
	if param.IPv4 != "" {
		return doIPv4(param.IPv4, param.Depth, &param.DB)
	}
	return nil
}

func doIPv4(ipv4 string, depth int, opt *db.Opt) error {
	db, err := db.New(opt)
	if err != nil {
		return xerrors.Errorf("postgres initialize error: %w", err)
	}
	addr := net.ParseIP(ipv4)

	// print thet flows of passive nodes
	pflows, err := db.FindPassiveFlows([]net.IP{addr})
	if err != nil {
		return xerrors.Errorf("find active flows error: %w", err)
	}
	for _, flows := range pflows {
		pn := flows[0].PassiveNode
		fmt.Printf("%s:%d ('%s', pgid=%d)\n", pn.IPAddr, pn.Port, pn.Pname, pn.Pgid)

		printPassiveFlows(flows)
	}

	// print the flows of active nodes
	aflows, err := db.FindActiveFlows([]net.IP{addr})
	if err != nil {
		return xerrors.Errorf("find active flows error: %w", err)
	}
	for _, flows := range aflows {
		anode := flows[0].ActiveNode
		fmt.Printf("%s ('%s', pgid=%d)\n", anode.IPAddr, anode.Pname, anode.Pgid)

		printActiveFlows(flows)
	}

	return nil
}

func printPassiveFlows(flows []*db.Flow) {
	// No implementation of printing tree with depth > 1
	for _, flow := range flows {
		fmt.Printf("└<-- %s\n", flow.ActiveNode)
	}
}

func printActiveFlows(flows []*db.Flow) {
	// No implementation of printing tree with depth > 1
	for _, flow := range flows {
		fmt.Printf("└--> %s\n", flow.PassiveNode)
	}
}
