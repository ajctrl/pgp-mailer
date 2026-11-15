// Package cli implements the client-side subcommands (healthcheck, admin).
// They talk to the running service over HTTP on the loopback interface and
// never open the queue database themselves: bbolt allows only one process.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"pgp-mailer/internal/config"
)

const usageAdmin = `usage:
  pgp-mailer admin failed list
  pgp-mailer admin failed retry <id>
  pgp-mailer admin failed delete <id>
  pgp-mailer admin quarantine list
  pgp-mailer admin quarantine delete <id>`

// baseURL derives the loopback URL of the service from LISTEN_ADDR.
func baseURL(getenv func(string) string) (string, error) {
	addr := strings.TrimSpace(getenv("LISTEN_ADDR"))
	if addr == "" {
		addr = config.DefaultListenAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("LISTEN_ADDR: %v", err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

// Healthcheck calls /healthz and returns the process exit code: 0 when the
// service answers 200, 1 otherwise.
func Healthcheck(getenv func(string) string, stderr io.Writer) int {
	base, err := baseURL(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(base + "/healthz")
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		fmt.Fprintf(stderr, "healthcheck: status %d %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}
	return 0
}

// Admin runs an admin subcommand against the admin API and returns the
// process exit code.
func Admin(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	var method, path string
	list := false
	switch {
	case len(args) == 2 && args[0] == "failed" && args[1] == "list":
		method, path, list = http.MethodGet, "/admin/v1/failed", true
	case len(args) == 3 && args[0] == "failed" && args[1] == "retry":
		method, path = http.MethodPost, "/admin/v1/failed/"+args[2]+"/retry"
	case len(args) == 3 && args[0] == "failed" && args[1] == "delete":
		method, path = http.MethodDelete, "/admin/v1/failed/"+args[2]
	case len(args) == 2 && args[0] == "quarantine" && args[1] == "list":
		method, path, list = http.MethodGet, "/admin/v1/quarantine", true
	case len(args) == 3 && args[0] == "quarantine" && args[1] == "delete":
		method, path = http.MethodDelete, "/admin/v1/quarantine/"+args[2]
	default:
		fmt.Fprintln(stderr, usageAdmin)
		return 2
	}
	if len(args) == 3 && strings.ContainsAny(args[2], "/?#% ") {
		fmt.Fprintln(stderr, "admin: invalid id")
		return 2
	}
	base, err := baseURL(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "admin:", err)
		return 1
	}
	// Read exactly as the server reads it, so both sides see the same token.
	token, err := config.Secret(getenv, "ADMIN_TOKEN")
	if err != nil {
		fmt.Fprintln(stderr, "admin:", err)
		return 1
	}
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		fmt.Fprintln(stderr, "admin:", err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "admin:", err)
		return 1
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		fmt.Fprintln(stderr, "admin:", err)
		return 1
	}
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error, Message string }
		_ = json.Unmarshal(body, &e)
		fmt.Fprintf(stderr, "admin: status %d: %s: %s\n", resp.StatusCode, e.Error, e.Message)
		return 1
	}
	if !list {
		var r struct{ ID, Result string }
		_ = json.Unmarshal(body, &r)
		fmt.Fprintf(stdout, "%s %s\n", r.ID, r.Result)
		return 0
	}
	var l struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &l); err != nil {
		fmt.Fprintln(stderr, "admin: unexpected response:", err)
		return 1
	}
	cols := []string{"id", "source", "level", "reason", "accepted_at", "failed_at", "delete_at"}
	if args[0] == "quarantine" {
		cols = []string{"id", "source", "level", "key_fingerprint", "accepted_at", "quarantined_at", "delete_at"}
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.ToUpper(strings.Join(cols, "\t")))
	for _, it := range l.Items {
		row := make([]string, len(cols))
		for i, c := range cols {
			row[i] = fmt.Sprint(it[c])
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()
	fmt.Fprintf(stdout, "%d item(s)\n", len(l.Items))
	return 0
}
