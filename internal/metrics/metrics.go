// Package metrics keeps the service counters and renders them, together
// with gauges sampled at scrape time, in the Prometheus text format. No
// label ever carries a title, a message or an address.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"
)

type rejectKey struct {
	source string
	code   int
}

type Metrics struct {
	mu        sync.Mutex
	accepted  map[string]uint64
	rejected  map[rejectKey]uint64
	delivered uint64
	failed    map[string]uint64
}

// New pre-registers every known series at zero so that increase() sees the
// very first event.
func New(sources []string, failReasons []string) *Metrics {
	m := &Metrics{
		accepted: map[string]uint64{},
		rejected: map[rejectKey]uint64{},
		failed:   map[string]uint64{},
	}
	for _, s := range sources {
		m.accepted[s] = 0
	}
	for _, r := range failReasons {
		m.failed[r] = 0
	}
	return m
}

func (m *Metrics) Accepted(source string) {
	m.mu.Lock()
	m.accepted[source]++
	m.mu.Unlock()
}

func (m *Metrics) Rejected(source string, code int) {
	m.mu.Lock()
	m.rejected[rejectKey{source, code}]++
	m.mu.Unlock()
}

func (m *Metrics) Delivered() {
	m.mu.Lock()
	m.delivered++
	m.mu.Unlock()
}

func (m *Metrics) Failed(reason string) {
	m.mu.Lock()
	m.failed[reason]++
	m.mu.Unlock()
}

// Gauges are sampled by the caller at scrape time.
type Gauges struct {
	Pending, Failed, Quarantined int
	StorageBytes, StorageLimit   int64
	KeyExpiry                    int64 // Unix seconds; 0 = key never expires
	KeyValid                     bool
}

func (m *Metrics) Write(w io.Writer, g Gauges) {
	m.mu.Lock()
	defer m.mu.Unlock()

	head := func(name, typ, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}

	head("pgp_mailer_accepted_total", "counter", "Notifications accepted (encrypted and persisted).")
	for _, s := range sortedKeys(m.accepted) {
		fmt.Fprintf(w, "pgp_mailer_accepted_total{source=%s} %d\n", strconv.Quote(s), m.accepted[s])
	}

	head("pgp_mailer_rejected_total", "counter", "Intake requests rejected, by HTTP status.")
	rk := make([]rejectKey, 0, len(m.rejected))
	for k := range m.rejected {
		rk = append(rk, k)
	}
	sort.Slice(rk, func(i, j int) bool {
		if rk[i].source != rk[j].source {
			return rk[i].source < rk[j].source
		}
		return rk[i].code < rk[j].code
	})
	for _, k := range rk {
		fmt.Fprintf(w, "pgp_mailer_rejected_total{source=%s,code=\"%d\"} %d\n", strconv.Quote(k.source), k.code, m.rejected[k])
	}

	head("pgp_mailer_delivered_total", "counter", "Messages handed over to the SMTP server.")
	fmt.Fprintf(w, "pgp_mailer_delivered_total %d\n", m.delivered)

	head("pgp_mailer_failed_total", "counter", "Messages moved to the failed queue.")
	for _, r := range sortedKeys(m.failed) {
		fmt.Fprintf(w, "pgp_mailer_failed_total{reason=%s} %d\n", strconv.Quote(r), m.failed[r])
	}

	head("pgp_mailer_queue_messages", "gauge", "Messages in each queue.")
	fmt.Fprintf(w, "pgp_mailer_queue_messages{state=\"pending\"} %d\n", g.Pending)
	fmt.Fprintf(w, "pgp_mailer_queue_messages{state=\"failed\"} %d\n", g.Failed)
	fmt.Fprintf(w, "pgp_mailer_queue_messages{state=\"quarantined\"} %d\n", g.Quarantined)

	head("pgp_mailer_storage_bytes", "gauge", "Logical bytes stored in the queue database.")
	fmt.Fprintf(w, "pgp_mailer_storage_bytes %d\n", g.StorageBytes)
	head("pgp_mailer_storage_limit_bytes", "gauge", "Application limit on stored logical bytes.")
	fmt.Fprintf(w, "pgp_mailer_storage_limit_bytes %d\n", g.StorageLimit)

	if g.KeyExpiry != 0 {
		head("pgp_mailer_key_expiry_timestamp_seconds", "gauge", "Expiry of the recipient key (absent if it never expires).")
		fmt.Fprintf(w, "pgp_mailer_key_expiry_timestamp_seconds %d\n", g.KeyExpiry)
	}
	head("pgp_mailer_key_valid", "gauge", "1 if the recipient key is currently usable for encryption.")
	valid := 0
	if g.KeyValid {
		valid = 1
	}
	fmt.Fprintf(w, "pgp_mailer_key_valid %d\n", valid)
}

func sortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
