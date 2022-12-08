// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/util/mak"
	"tailscale.com/version"
)

var serveCmd = newServeCommand(&serveEnv{})

// newServeCommand returns a new "serve" subcommand using e as its environmment.
func newServeCommand(e *serveEnv) *ffcli.Command {
	return &ffcli.Command{
		Name:      "serve",
		ShortHelp: "[ALPHA] Serve from your Tailscale node",
		ShortUsage: strings.TrimSpace(`
serve https:<serve-port> <mount-point> <target> [off]
  serve tcp+tls:<serve-port> tcp[+tls]://localhost:<local-port> [off]
  serve status [--json]
`),
		LongHelp: strings.TrimSpace(`
*** ALPHA; all of this is subject to change ***

The 'tailscale serve' set of commands allows you to serve
content and local servers from your Tailscale node to
your tailnet. 

You can also choose to enable the Tailscale Funnel with:
'tailscale funnel on'. Funnel allows you to publish
a 'tailscale serve' server publicly, open to the entire
internet. See https://tailscale.com/funnel.

EXAMPLES
  - To proxy requests to a web server at 127.0.0.1:3000:
    $ tailscale serve https:443 / http://127.0.0.1:3000

  - To serve a single file or a directory of files:
    $ tailscale serve https:443 / /home/alice/blog/index.html
    $ tailscale serve https:443 /images/ /home/alice/blog/images

  - To serve simple static text:
    $ tailscale serve https:443 / text:"Hello, world!"

  - To forward TLS over TCP to a local TCP server on port 8443:
    $ tailscale serve tcp+tls:443 tcp+tls://localhost:8443

  - To forward raw, TLS-terminated TCP packets to a local TCP server on port 5432:
    $ tailscale serve tcp+tls:443 tcp://localhost:5432
`),
		Exec:      e.runServe,
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "show current serve/funnel status",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
		},
	}
}

func (e *serveEnv) newFlags(name string, setup func(fs *flag.FlagSet)) *flag.FlagSet {
	onError, out := flag.ExitOnError, Stderr
	if e.testFlagOut != nil {
		onError, out = flag.ContinueOnError, e.testFlagOut
	}
	fs := flag.NewFlagSet(name, onError)
	fs.SetOutput(out)
	if setup != nil {
		setup(fs)
	}
	return fs
}

// serveEnv is the environment the serve command runs within. All I/O should be
// done via serveEnv methods so that it can be faked out for tests.
//
// It also contains the flags, as registered with newServeCommand.
type serveEnv struct {
	// flags
	json       bool // output JSON (status only for now)
	funnelPort uint // Port to expose the Funnel on (default 443)

	// optional stuff for tests:
	testFlagOut              io.Writer
	testGetServeConfig       func(context.Context) (*ipn.ServeConfig, error)
	testSetServeConfig       func(context.Context, *ipn.ServeConfig) error
	testGetLocalClientStatus func(context.Context) (*ipnstate.Status, error)
	testStdout               io.Writer
}

// getSelfDNSName returns the DNS name of the current node.
// The trailing dot is removed.
// Returns an error if local client status fails.
func (e *serveEnv) getSelfDNSName(ctx context.Context) (string, error) {
	st, err := e.getLocalClientStatus(ctx)
	if err != nil {
		return "", fmt.Errorf("getting client status: %w", err)
	}
	return strings.TrimSuffix(st.Self.DNSName, "."), nil
}

// getLocalClientStatus calls LocalClient.Status, checks if
// Status is ready.
// Returns error if unable to reach tailscaled or if self node is nil.
// Exits if status is not running or starting.
func (e *serveEnv) getLocalClientStatus(ctx context.Context) (*ipnstate.Status, error) {
	if e.testGetLocalClientStatus != nil {
		return e.testGetLocalClientStatus(ctx)
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return nil, fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s\n", description)
		os.Exit(1)
	}
	if st.Self == nil {
		return nil, errors.New("no self node")
	}
	return st, nil
}

func (e *serveEnv) getServeConfig(ctx context.Context) (*ipn.ServeConfig, error) {
	if e.testGetServeConfig != nil {
		return e.testGetServeConfig(ctx)
	}
	return localClient.GetServeConfig(ctx)
}

func (e *serveEnv) setServeConfig(ctx context.Context, c *ipn.ServeConfig) error {
	if e.testSetServeConfig != nil {
		return e.testSetServeConfig(ctx, c)
	}
	return localClient.SetServeConfig(ctx, c)
}

// runServe is the entry point for the "serve" subcommand, managing Web
// serve config types like proxy, path, and text.
//
// Examples:
// - tailscale serve / proxy 3000
// - tailscale serve /images/ path /var/www/images/
// - tailscale --serve-port=10000 serve /motd.txt text "Hello, world!"
func (e *serveEnv) runServe(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return flag.ErrHelp
	}

	// Undocumented debug command (not using ffcli subcommands) to set raw
	// configs from stdin for now (2022-11-13).
	if len(args) == 1 && args[0] == "set-raw" {
		valb, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		sc := new(ipn.ServeConfig)
		if err := json.Unmarshal(valb, sc); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		return localClient.SetServeConfig(ctx, sc)
	}

	parseServePort := func(portStr string) (uint16, error) {
		port64, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return 0, err
		}
		port := uint16(port64)
		// make sure port is 443, 8443 or 10000
		if port != 443 && port != 8443 && port != 10000 {
			return 0, fmt.Errorf("serve-port %d is invalid; must be 443, 8443 or 10000", port)
		}
		return port, nil
	}

	srvType, srvPortStr, found := strings.Cut(args[0], ":")
	if !found {
		return flag.ErrHelp
	}

	turnOff := "off" == args[len(args)-1]

	if len(args) < 2 || srvType == "https" && len(args) < 3 && !turnOff {
		fmt.Fprintf(os.Stderr, "error: invalid number of arguments\n\n")
		return flag.ErrHelp
	}

	srvPort, err := parseServePort(srvPortStr)
	if err != nil {
		return err
	}

	switch srvType {
	case "https":
		mount, err := cleanMountPoint(args[1])
		if err != nil {
			return err
		}
		if turnOff {
			return e.handleWebServeRemove(ctx, srvPort, mount)
		}
		return e.handleWebServe(ctx, srvPort, mount, args[2])
	case "tcp+tls":
		if turnOff {
			return e.handleTCPServeRemove(ctx, srvPort)
		}
		return e.handleTCPServe(ctx, srvPort, args[1])
	default:
		fmt.Fprintf(os.Stderr, "error: invalid serve type %q\n", srvType)
		fmt.Fprint(os.Stderr, "must be one of: https:<serve-port> or tcp+tls:<serve-port>\n\n", srvType)
		return flag.ErrHelp
	}
}

// handleWebServe handles the "tailscale serve https:..." subcommand.
// It configures the serve config to forward HTTPS connections to the
// given target.
//
// Examples:
//   - tailscale serve https:443 / http://localhost:3000
//   - tailscale serve https:8443 /files/ /home/alice/shared-files/
//   - tailscale serve https:10000 /motd.txt text:"Hello, world!"
func (e *serveEnv) handleWebServe(ctx context.Context, srvPort uint16, mount, target string) error {
	h := new(ipn.HTTPHandler)

	ts, _, _ := strings.Cut(target, ":")
	switch {
	case ts == "text":
		text := strings.TrimPrefix(target, "text:")
		if text == "" {
			return errors.New("unable to serve; text cannot be an empty string")
		}
		h.Text = text
	case isProxyTarget(target):
		t, err := expandProxyTarget(target)
		if err != nil {
			return err
		}
		h.Proxy = t
	default: // assume path
		if version.IsSandboxedMacOS() {
			// don't allow path serving for now on macOS (2022-11-15)
			return fmt.Errorf("path serving is not supported if sandboxed on macOS")
		}
		if !filepath.IsAbs(target) {
			fmt.Fprintf(os.Stderr, "error: path must be absolute\n\n")
			return flag.ErrHelp
		}
		target = filepath.Clean(target)
		fi, err := os.Stat(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid path: %v\n\n", err)
			return flag.ErrHelp
		}
		if fi.IsDir() && !strings.HasSuffix(mount, "/") {
			// dir mount points must end in /
			// for relative file links to work
			mount += "/"
		}
		h.Path = target
	}

	cursc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	if sc.IsTCPForwardingOnPort(srvPort) {
		fmt.Fprintf(os.Stderr, "error: cannot serve web; already serving TCP\n")
		return flag.ErrHelp
	}

	mak.Set(&sc.TCP, srvPort, &ipn.TCPPortHandler{HTTPS: true})

	if _, ok := sc.Web[hp]; !ok {
		mak.Set(&sc.Web, hp, new(ipn.WebServerConfig))
	}
	mak.Set(&sc.Web[hp].Handlers, mount, h)

	for k, v := range sc.Web[hp].Handlers {
		if v == h {
			continue
		}
		// If the new mount point ends in / and another mount point
		// shares the same prefix, remove the other handler.
		// (e.g. /foo/ overwrites /foo)
		// The opposite example is also handled.
		m1 := strings.TrimSuffix(mount, "/")
		m2 := strings.TrimSuffix(k, "/")
		if m1 == m2 {
			delete(sc.Web[hp].Handlers, k)
			continue
		}
	}

	if !reflect.DeepEqual(cursc, sc) {
		if err := e.setServeConfig(ctx, sc); err != nil {
			return err
		}
	}

	return nil
}

func isProxyTarget(target string) bool {
	if strings.HasPrefix(target, "http") && strings.Index(target, "://") > 0 {
		return true
	}
	// support "localhost:3000", for example
	_, portStr, _ := strings.Cut(target, ":")
	if allNumeric(portStr) && strings.HasSuffix(target, ":"+portStr) {
		return true
	}
	return false
}

func allNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// handleWebServeRemove removes a web handler from the serve config.
// The srvPort argument is the serving port and the mount argument is
// the mount point or registered path to remove.
func (e *serveEnv) handleWebServeRemove(ctx context.Context, srvPort uint16, mount string) error {
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	if sc == nil {
		return errors.New("error: serve config does not exist")
	}
	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	if sc.IsTCPForwardingOnPort(srvPort) {
		return errors.New("cannot remove web handler; currently serving TCP")
	}
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))
	if !sc.WebHandlerExists(hp, mount) {
		return errors.New("error: handler does not exist")
	}
	// delete existing handler, then cascade delete if empty
	delete(sc.Web[hp].Handlers, mount)
	if len(sc.Web[hp].Handlers) == 0 {
		delete(sc.Web, hp)
		delete(sc.TCP, srvPort)
	}
	// clear empty maps mostly for testing
	if len(sc.Web) == 0 {
		sc.Web = nil
	}
	if len(sc.TCP) == 0 {
		sc.TCP = nil
	}
	if err := e.setServeConfig(ctx, sc); err != nil {
		return err
	}
	return nil
}

func cleanMountPoint(mount string) (string, error) {
	if mount == "" {
		return "", errors.New("mount point cannot be empty")
	}
	if !strings.HasPrefix(mount, "/") {
		mount = "/" + mount
	}
	c := path.Clean(mount)
	if mount == c || mount == c+"/" {
		return mount, nil
	}
	return "", fmt.Errorf("invalid mount point %q", mount)
}

func expandProxyTarget(target string) (string, error) {
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return "", fmt.Errorf("parsing url: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "https+insecure":
		// ok
	default:
		return "", fmt.Errorf("must be a URL starting with http://, https://, or https+insecure://")
	}

	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if port == 0 || err != nil {
		return "", fmt.Errorf("invalid port %q: %w", u.Port(), err)
	}

	host := u.Hostname()
	switch host {
	case "localhost", "127.0.0.1":
		host = "127.0.0.1"
	default:
		return "", fmt.Errorf("only localhost or 127.0.0.1 proxies are currently supported")
	}
	url := u.Scheme + "://" + host
	if u.Port() != "" {
		url += ":" + u.Port()
	}
	return url, nil
}

// handleTCPServe handles the "tailscale serve tcp+tls:..." subcommand.
// It configures the serve config to forward TCP connections to the
// given target.
//
// Examples:
//   - tailscale serve tcp+tls:443 tcp+tls://localhost:5432
//   - tailscale serve tcp+tls:8443 tcp+tls://localhost:4430
//   - tailscale serve tcp+tls:10000 tcp://localhost:8080 (TLS terminated)
func (e *serveEnv) handleTCPServe(ctx context.Context, srvPort uint16, target string) error {
	u, err := url.Parse(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid target %q: %v\n\n", target, err)
		return flag.ErrHelp
	}

	var terminateTLS bool
	switch u.Scheme {
	case "tcp":
		terminateTLS = true
	case "tcp+tls":
		terminateTLS = false
	default:
		fmt.Fprintf(os.Stderr, "error: invalid TCP target %q\n\n", target)
		return flag.ErrHelp
	}

	host, targetPortStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid TCP target %q: %v\n\n", target, err)
		return flag.ErrHelp
	}

	switch host {
	case "localhost", "127.0.0.1":
		// ok
	default:
		fmt.Fprintf(os.Stderr, "error: invalid TCP target %q\n", target)
		fmt.Fprint(os.Stderr, "must be one of: localhost or 127.0.0.1\n\n", target)
		return flag.ErrHelp
	}

	if p, err := strconv.ParseUint(targetPortStr, 10, 16); p == 0 || err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid port %q\n\n", targetPortStr)
		return flag.ErrHelp
	}

	cursc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	fwdAddr := "127.0.0.1:" + targetPortStr

	if sc.IsServingWeb(srvPort) {
		return fmt.Errorf("cannot serve TCP; already serving web on %d", srvPort)
	}

	mak.Set(&sc.TCP, srvPort, &ipn.TCPPortHandler{TCPForward: fwdAddr})

	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	if terminateTLS {
		sc.TCP[srvPort].TerminateTLS = dnsName
	}

	if !reflect.DeepEqual(cursc, sc) {
		if err := e.setServeConfig(ctx, sc); err != nil {
			return err
		}
	}

	return nil
}

// handleTCPServeRemove removes the TCP forwarding configuration for the
// given srvPort, or serving port.
func (e *serveEnv) handleTCPServeRemove(ctx context.Context, srvPort uint16) error {
	cursc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	if sc.IsServingWeb(srvPort) {
		return fmt.Errorf("unable to remove; serving web, not TCP forwarding on serve port %d", srvPort)
	}
	if ph := sc.GetTCPPortHandler(srvPort); ph != nil {
		delete(sc.TCP, srvPort)
		// clear map mostly for testing
		if len(sc.TCP) == 0 {
			sc.TCP = nil
		}
		return e.setServeConfig(ctx, sc)
	}
	return errors.New("error: serve config does not exist")
}

// runServeStatus is the entry point for the "serve status"
// subcommand and prints the current serve config.
//
// Examples:
//   - tailscale status
//   - tailscale status --json
func (e *serveEnv) runServeStatus(ctx context.Context, args []string) error {
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	if e.json {
		j, err := json.MarshalIndent(sc, "", "  ")
		if err != nil {
			return err
		}
		j = append(j, '\n')
		e.stdout().Write(j)
		return nil
	}
	if sc == nil || (len(sc.TCP) == 0 && len(sc.Web) == 0 && len(sc.AllowFunnel) == 0) {
		printf("No serve config\n")
		return nil
	}
	st, err := e.getLocalClientStatus(ctx)
	if err != nil {
		return err
	}
	if sc.IsTCPForwardingAny() {
		if err := printTCPStatusTree(ctx, sc, st); err != nil {
			return err
		}
		printf("\n")
	}
	for hp := range sc.Web {
		printWebStatusTree(sc, hp)
		printf("\n")
	}
	// warn when funnel on without handlers
	for hp, a := range sc.AllowFunnel {
		if !a {
			continue
		}
		_, portStr, _ := net.SplitHostPort(string(hp))
		p, _ := strconv.ParseUint(portStr, 10, 16)
		if _, ok := sc.TCP[uint16(p)]; !ok {
			printf("WARNING: funnel=on for %s, but no serve config\n", hp)
		}
	}
	return nil
}

func (e *serveEnv) stdout() io.Writer {
	if e.testStdout != nil {
		return e.testStdout
	}
	return os.Stdout
}

func printTCPStatusTree(ctx context.Context, sc *ipn.ServeConfig, st *ipnstate.Status) error {
	dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
	for p, h := range sc.TCP {
		if h.TCPForward == "" {
			continue
		}
		hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(p))))
		tlsStatus := "TLS over TCP"
		if h.TerminateTLS != "" {
			tlsStatus = "TLS terminated"
		}
		fStatus := "tailnet only"
		if sc.AllowFunnel[hp] {
			fStatus = "Funnel on"
		}
		printf("|-- tcp://%s (%s, %s)\n", hp, tlsStatus, fStatus)
		for _, a := range st.TailscaleIPs {
			ipp := net.JoinHostPort(a.String(), strconv.Itoa(int(p)))
			printf("|-- tcp://%s\n", ipp)
		}
		printf("|--> tcp://%s\n", h.TCPForward)
	}
	return nil
}

func printWebStatusTree(sc *ipn.ServeConfig, hp ipn.HostPort) {
	if sc == nil {
		return
	}
	fStatus := "tailnet only"
	if sc.AllowFunnel[hp] {
		fStatus = "Funnel on"
	}
	host, portStr, _ := net.SplitHostPort(string(hp))
	if portStr == "443" {
		printf("https://%s (%s)\n", host, fStatus)
	} else {
		printf("https://%s:%s (%s)\n", host, portStr, fStatus)
	}
	srvTypeAndDesc := func(h *ipn.HTTPHandler) (string, string) {
		switch {
		case h.Path != "":
			return "path", h.Path
		case h.Proxy != "":
			return "proxy", h.Proxy
		case h.Text != "":
			return "text", "\"" + elipticallyTruncate(h.Text, 20) + "\""
		}
		return "", ""
	}

	var mounts []string
	for k := range sc.Web[hp].Handlers {
		mounts = append(mounts, k)
	}
	sort.Slice(mounts, func(i, j int) bool {
		return len(mounts[i]) < len(mounts[j])
	})
	maxLen := len(mounts[len(mounts)-1])

	for _, m := range mounts {
		h := sc.Web[hp].Handlers[m]
		t, d := srvTypeAndDesc(h)
		printf("%s %s%s %-5s %s\n", "|--", m, strings.Repeat(" ", maxLen-len(m)), t, d)
	}
}

func elipticallyTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
