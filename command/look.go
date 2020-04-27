package command

import (
	"fmt"
	"net"
	"time"

	"github.com/yuuki/shawk/config"
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
	Since string
	Until string
}

// Look runs look subcommand.
func Look(param *LookParam) error {
	var (
		since, until time.Time
		err          error
	)
	if param.Since != "" {
		since, err = durationFromString(param.Since)
		if err != nil {
			return err
		}
	}
	if param.Until != "" {
		until, err = durationFromString(param.Until)
		if err != nil {
			return err
		}
	}

	if param.IPv4 != "" {
		return doIPv4(param.IPv4, param.Depth, since, until)
	}
	return nil
}

func durationFromString(s string) (time.Time, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, xerrors.Errorf("time parse error: %w", err)
	}
	return time.Now().Add(-d), nil
}

func doIPv4(ipv4 string, depth int, since, until time.Time) error {
	dbCon, err := db.New(config.Config.CMDB.URL)
	if err != nil {
		return xerrors.Errorf("postgres initialize error: %w", err)
	}
	addr := net.ParseIP(ipv4)

	pflows, err := dbCon.FindPassiveFlows(&db.FindFlowsCond{
		Addrs: []net.IP{addr},
		Since: since,
		Until: until,
	})
	if err != nil {
		return xerrors.Errorf("find active flows error: %w", err)
	}

	// print thet flows of passive nodes
	for _, flows := range pflows {
		pn := flows[0].PassiveNode
		fmt.Printf("%s:%d ('%s', pgid=%d)\n", pn.IPAddr, pn.Port, pn.Pname, pn.Pgid)

		printPassiveFlows(flows)
	}

	aflows, err := dbCon.FindActiveFlows(&db.FindFlowsCond{
		Addrs: []net.IP{addr},
		Since: since,
		Until: until,
	})
	if err != nil {
		return xerrors.Errorf("find active flows error: %w", err)
	}

	// print the flows of active nodes
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
