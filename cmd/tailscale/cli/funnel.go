// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/exp/slices"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
)

var funnelCmd = newFunnelCommand(&serveEnv{})

// newFunnelCommand returns a new "funnel" subcommand using e as its environment.
// The funnel subcommand is used to turn on/off the Funnel service.
// Funnel is off by default.
// Funnel allows you to publish a 'tailscale serve' server publicly, open to the
// entire internet.
// newFunnelCommand shares the same serveEnv as the "serve" subcommand. See
// newServeCommand and serve.go for more details.
func newFunnelCommand(e *serveEnv) *ffcli.Command {
	return &ffcli.Command{
		Name:      "funnel",
		ShortHelp: "turn Tailscale Funnel on or off",
		ShortUsage: strings.TrimSpace(`
funnel [--serve-port=<port>] {on|off}
  funnel status [--json]
`),
		LongHelp: strings.Join([]string{
			"Funnel allows you to publish a 'tailscale serve'",
			"server publicly, open to the entire internet.",
			"",
			"Turning off Funnel only turns off serving to the internet.",
			"It does not affect serving to your tailnet.",
		}, "\n"),
		Exec: e.runFunnel,
		FlagSet: e.newFlags("serve", func(fs *flag.FlagSet) {
			fs.UintVar(&e.funnelPort, "serve-port", 443, "port to serve on (443, 8443 or 10000)")
		}),
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "show current serve/funnel status",
				FlagSet: e.newFlags("funnel-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
		},
	}
}

// runFunnel is the entry point for the "tailscale funnel" subcommand and
// manages turning on/off funnel. Funnel is off by default.
//
// Note: funnel is only supported on single DNS name for now. (2022-11-15)
func (e *serveEnv) runFunnel(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	switch e.funnelPort {
	case 443, 8443, 10000:
		// ok
	default:
		fmt.Fprintf(os.Stderr, "serve-port %d is invalid; must be 443, 8443 or 10000\n\n", e.funnelPort)
		return flag.ErrHelp
	}

	var on bool
	switch args[0] {
	case "on", "off":
		on = args[0] == "on"
	default:
		return flag.ErrHelp
	}
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	st, err := e.getLocalClientStatus(ctx)
	if err != nil {
		return fmt.Errorf("getting client status: %w", err)
	}
	if err := checkHasAccess(st.Self.Capabilities); err != nil {
		return err
	}
	dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
	hp := ipn.HostPort(dnsName + ":" + strconv.Itoa(int(e.funnelPort)))
	if on == sc.AllowFunnel[hp] {
		// Nothing to do.
		return nil
	}
	if on {
		mak.Set(&sc.AllowFunnel, hp, true)
	} else {
		delete(sc.AllowFunnel, hp)
		// clear map mostly for testing
		if len(sc.AllowFunnel) == 0 {
			sc.AllowFunnel = nil
		}
	}
	if err := e.setServeConfig(ctx, sc); err != nil {
		return err
	}
	// warn when funnel on without handlers
	if _, ok := sc.TCP[uint16(e.funnelPort)]; !ok {
		fmt.Fprintf(os.Stderr, "WARNING: funnel=on for %s, but no serve config\n", hp)
	}
	return nil
}

// checkHasAccess checks three things: 1) an invite was used to join the
// Funnel alpha; 2) HTTPS is enabled; 3) the node has the "funnel" attribute.
// If any of these are false, an error is returned describing the problem.
//
// The nodeAttrs arg should be the node's Self.Capabilities which should contain
// the attribute we're checking for and possibly warning-capabilities for Funnel.
func checkHasAccess(nodeAttrs []string) error {
	if slices.Contains(nodeAttrs, tailcfg.CapabilityWarnFunnelNoInvite) {
		return errors.New("Funnel not available; an invite is required to join the alpha. See https://tailscale.com/kb/1223/tailscale-funnel/.")
	}
	if slices.Contains(nodeAttrs, tailcfg.CapabilityWarnFunnelNoHTTPS) {
		return errors.New("Funnel not available; HTTPS must be enabled. See https://tailscale.com/kb/1153/enabling-https/.")
	}
	if !slices.Contains(nodeAttrs, tailcfg.NodeAttrFunnel) {
		return errors.New("Funnel not available; \"funnel\" node attribute not set. See https://tailscale.com/kb/1223/tailscale-funnel/.")
	}
	return nil
}
