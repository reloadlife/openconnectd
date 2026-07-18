// Command openconnectctl is a small CLI for a running openconnectd, mirroring
// the control tools of the sibling daemons. It talks to the daemon's loopback
// REST API via pkg/api.
//
//	openconnectctl [--config FILE] [--url URL] [--token TOK] <command> [args]
//
// Commands:
//
//	version                         daemon + ocserv version
//	instances                       list servers
//	sessions [instance]             live connections (occtl)
//	clients <instance>              provisioned users
//	config <instance> <cn>          print a user's importable profile
//	disconnect <instance> <cn>      kick a live session
//	rm-client <instance> <cn>       revoke + delete a user
//
// URL/token resolution: --url/--token flags, else OPENCONNECTD_URL /
// OPENCONNECTD_TOKEN env, else --config (an openconnectd.yaml: listen + token).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/reloadlife/openconnectd/internal/config"
	"github.com/reloadlife/openconnectd/pkg/api"
)

func main() {
	fs := flag.NewFlagSet("openconnectctl", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "openconnectd.yaml to read url+token from")
	url := fs.String("url", "", "daemon base URL (default http://127.0.0.1:51990)")
	token := fs.String("token", "", "bearer token")
	fs.Usage = usage
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	args := fs.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	base, tok := resolve(*cfgPath, *url, *token)
	c, err := api.NewClient(base, api.WithToken(tok))
	if err != nil {
		die(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	switch args[0] {
	case "version":
		v, err := c.Version(ctx)
		if err != nil {
			die(err)
		}
		fmt.Printf("openconnectd %s  ocserv %s  (%s)\n", v.Version, v.OcservVer, v.OcservPath)
	case "instances":
		list, err := c.ListInstances(ctx)
		if err != nil {
			die(err)
		}
		w := tab()
		fmt.Fprintln(w, "NAME\tUP\tAUTH\tCAMOUFLAGE\tPOOL\tCLIENTS\tENDPOINT")
		for _, in := range list {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
				in.Name, yn(in.Up), orDash(string(in.AuthMode)), yn(in.Camouflage.Enabled),
				orDash(in.PoolCIDR), in.ClientCount, orDash(in.PublicEndpoint))
		}
		w.Flush()
	case "sessions":
		inst := ""
		if len(args) > 1 {
			inst = args[1]
		}
		list, err := c.Sessions(ctx, inst)
		if err != nil {
			die(err)
		}
		w := tab()
		fmt.Fprintln(w, "USER\tINSTANCE\tVPN IP\tREMOTE IP\tRX\tTX\tDTLS\tSINCE")
		for _, s := range list {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
				s.CommonName, s.InstanceName, orDash(s.VPNAddress), orDash(s.RemoteIP),
				s.RxBytes, s.TxBytes, yn(s.DTLS), since(s.ConnectedAt))
		}
		w.Flush()
	case "clients":
		if len(args) < 2 {
			die(fmt.Errorf("usage: clients <instance>"))
		}
		list, err := c.ListClients(ctx, args[1])
		if err != nil {
			die(err)
		}
		w := tab()
		fmt.Fprintln(w, "COMMON NAME\tNAME\tAUTH\tSUSPENDED\tCERT SERIAL")
		for _, cl := range list {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				cl.CommonName, orDash(cl.Name), orDash(string(cl.AuthMode)),
				yn(cl.Suspended), orDash(cl.CertSerial))
		}
		w.Flush()
	case "config":
		if len(args) < 3 {
			die(fmt.Errorf("usage: config <instance> <common-name>"))
		}
		out, err := c.ClientConfig(ctx, args[1], args[2])
		if err != nil {
			die(err)
		}
		fmt.Print(out)
	case "disconnect":
		if len(args) < 3 {
			die(fmt.Errorf("usage: disconnect <instance> <common-name>"))
		}
		if err := c.Disconnect(ctx, args[1], args[2]); err != nil {
			die(err)
		}
		fmt.Printf("disconnected %s@%s\n", args[2], args[1])
	case "rm-client":
		if len(args) < 3 {
			die(fmt.Errorf("usage: rm-client <instance> <common-name>"))
		}
		if err := c.DeleteClient(ctx, args[1], args[2]); err != nil {
			die(err)
		}
		fmt.Printf("removed %s@%s (cert revoked)\n", args[2], args[1])
	default:
		usage()
		os.Exit(2)
	}
}

func resolve(cfgPath, url, token string) (base, tok string) {
	base, tok = url, token
	if base == "" {
		base = os.Getenv("OPENCONNECTD_URL")
	}
	if tok == "" {
		tok = os.Getenv("OPENCONNECTD_TOKEN")
	}
	if (base == "" || tok == "") && cfgPath != "" {
		if c, err := config.Load(cfgPath); err == nil {
			if base == "" && c.Listen != "" {
				base = "http://" + c.Listen
			}
			if tok == "" {
				tok = c.Token
			}
		}
	}
	if base == "" {
		base = "http://127.0.0.1:51990"
	}
	return base, tok
}

func tab() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func since(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return time.Since(t).Round(time.Second).String()
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "openconnectctl:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `openconnectctl — control a running openconnectd

Usage:
  openconnectctl [--config FILE] [--url URL] [--token TOK] <command> [args]

Commands:
  version
  instances
  sessions [instance]
  clients <instance>
  config <instance> <common-name>
  disconnect <instance> <common-name>
  rm-client <instance> <common-name>

URL/token: --url/--token, else OPENCONNECTD_URL / OPENCONNECTD_TOKEN, else --config.
`)
}
