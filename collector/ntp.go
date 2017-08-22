// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !nontp

package collector

import (
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/beevik/ntp"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	maxDispersion = 16 // aka MAXDISP
	phi_us        = 15 // phi is 15e-6 (s)
	maxPoll       = 17 // log2 max poll interval (~36 h)

	maxDistance = (1500000 + (phi_us * (1 << maxPoll))) * time.Microsecond // 1.5s is MAXDIST from ntp.org, 1.0 is from RFC5905
)

var (
	ntpServer          = flag.String("collector.ntp.server", "127.0.0.1", "NTP server to use for ntp collector")
	ntpServerIsLocal   = flag.Bool("collector.ntp.server-is-local", false, "Certify that collector.ntp.server address is the same local host as this collector.")
	ntpIpTTL           = flag.Int("collector.ntp.ip-ttl", 1, "IP TTL to use while sending NTP query")
	ntpProtocolVersion = flag.Int("collector.ntp.protocol-version", 4, "NTP protocol version")
	ntpMaxDistance     = flag.Duration("collector.ntp.max-distance", maxDistance, "Max accumulated distance to the root")
	ntpOffsetTolerance = flag.Duration("collector.ntp.local-offset-tolerance", time.Millisecond, "Offset between local clock and local ntpd time to tolerate")

	leapMidnight time.Time
)

type ntpCollector struct {
	stratum, leap, rtt, offset, reftime, root_delay, root_dispersion, sanity typedDesc
}

func init() {
	Factories["ntp"] = NewNtpCollector
}

// NewNtpCollector returns a new Collector exposing sanity of local NTP server.
// Default definition of "local" is:
// - collector.ntp.server address is a loopback address (or collector.ntp.server-is-mine flag is turned on)
// - the server is reachable with outgoin IP_TTL = 1
func NewNtpCollector() (Collector, error) {
	ipaddr := net.ParseIP(*ntpServer)
	if !*ntpServerIsLocal && (ipaddr == nil || !ipaddr.IsLoopback()) {
		return nil, fmt.Errorf("only IP address of local NTP server is valid for -collector.ntp.server")
	}

	if *ntpProtocolVersion < 2 || *ntpProtocolVersion > 4 {
		return nil, fmt.Errorf("invalid NTP protocol version %d; must be 2, 3, or 4", *ntpProtocolVersion)
	}

	if *ntpOffsetTolerance < 0 {
		return nil, fmt.Errorf("Offset tolerance must be non-negative")
	}

	return &ntpCollector{
		stratum: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "ntp", "stratum"),
			"NTP server stratum.",
			nil, nil,
		), prometheus.GaugeValue},
		leap: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "ntp", "leap"),
			"Leap second flag raw value.",
			nil, nil,
		), prometheus.GaugeValue},
		rtt: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "ntp", "rtt"),
			"RTT.",
			nil, nil,
		), prometheus.GaugeValue},
		offset: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "ntp", "offset"),
			"ClockOffset.",
			nil, nil,
		), prometheus.GaugeValue},
		reftime: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "ntp", "reftime"),
			"ReferenceTime raw value.",
			nil, nil,
		), prometheus.GaugeValue},
		root_delay: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "ntp", "root_delay"),
			"RootDelay raw value.",
			nil, nil,
		), prometheus.GaugeValue},
		root_dispersion: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "ntp", "root_dispersion"),
			"RootDispersion raw value.",
			nil, nil,
		), prometheus.GaugeValue},
		sanity: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "ntp", "sanity"),
			"NTP server is sane according to ntpdate and RFC5905 heuristics.",
			nil, nil,
		), prometheus.GaugeValue},
	}, nil
}

func (c *ntpCollector) Update(ch chan<- prometheus.Metric) error {
	resp, err := ntp.QueryWithOptions(*ntpServer, ntp.QueryOptions{
		Version: *ntpProtocolVersion,
		TTL:     *ntpIpTTL,
		Timeout: time.Second, // default `ntpdate` timeout
	})
	if err != nil {
		// XXX: should it report `sanity=0` in this case?
		return fmt.Errorf("couldn't get SNTP reply: %s", err)
	}

	// Reference Timestamp: Time when the system clock was last set or
	// corrected. Semantics of this value seems to vary across NTP server
	// implementations: it may be both NTP-clock time and system wall-clock
	// time of this event. :-( So (T3 - ReferenceTime) is not true
	// "freshness" as it may be actually NEGATIVE, so it's not exposed as
	// metrics to avoid confusion.
	freshness := resp.Time.Sub(resp.ReferenceTime)

	// (Lambda := RootDelay/2 + RootDispersion) check against MAXDISP (16s)
	// is required as ntp.org ntpd may report sane other fields while
	// giving quite erratic clock. The check is declared in packet() at
	// https://tools.ietf.org/html/rfc5905#appendix-A.5.1.1.
	lambda := resp.RootDelay/2 + resp.RootDispersion

	// Also, RFC5905 suggests more strict check in fit(), that suggest that
	// root_delay should be less than MAXDIST + PHI * LOG2D(s.poll).
	// MAXPOLL is 17, so it is approximately at most (1s + 15e-6 * 2**17) =
	// 2.96608 s, but MAXDIST and MAXPOLL are confugurable values in the
	// reference implementation, so only MAXDISP check has hardcoded value.
	// root_delay should also have following summands
	// + Dispersion towards the peer
	// + jitter of the link to the peer
	// + PHI * (current_uptime - peer->uptime_of_last_update)
	// but all these values are 0 if only single NTP packet was sent.
	root_delay := (resp.RTT+resp.RootDelay)/2 + resp.RootDispersion

	// (-1*RTT/2 <= ClockOffset <= RTT/2) is equal to (T1 <= T2 && T3 <= T4).
	// That's not a true check that clock is in-sync (T1 <= T2 <= T3 <= T4),
	// but that's good enough as clock usually goes forward, so I assume
	// that T2 <= T3 and T1 <= T4.  It is used to detect the case when NTP
	// client wall-clock differs from NTP-clock in the NTP server that is
	// running on same machine (these two should be quite similar clock).
	// That's required for chrony as it starts relaying sane NTP clock
	// before system wall-clock is actually adjusted.
	//
	// ntpOffsetTolerance is added to avoid warning on following chrony
	// state that is _practically_ sane: RTT = 0.000174662,
	// ClockOffset = -0.000261665, Self-reported Offset = -0.000215618
	offset_margin := resp.RTT/2 + *ntpOffsetTolerance
	if resp.Leap == ntp.LeapAddSecond || resp.Leap == ntp.LeapDelSecond {
		// state of leapMidnight is cached as leap flag is dropped right after midnight
		leapMidnight = resp.Time.Truncate(24 * time.Hour).Add(24 * time.Hour)
	}
	if leapMidnight.Add(-24*time.Hour).Before(resp.Time) && resp.Time.Before(leapMidnight.Add(24*time.Hour)) {
		// tolerate leap smearing
		offset_margin += time.Second
	}

	ch <- c.stratum.mustNewConstMetric(float64(resp.Stratum))
	ch <- c.leap.mustNewConstMetric(float64(resp.Leap))
	var reftime float64
	if resp.ReferenceTime.Unix() > 0 {
		// Go Zero is   0001-01-01 00:00:00 UTC
		// NTP Zero is  1900-01-01 00:00:00 UTC
		// UNIX Zero is 1970-01-01 00:00:00 UTC
		// so let's keep ALL ancient `reftime` values as zero
		reftime = float64(resp.ReferenceTime.UnixNano()) / 1e9
	}
	ch <- c.reftime.mustNewConstMetric(reftime)
	ch <- c.rtt.mustNewConstMetric(resp.RTT.Seconds())
	ch <- c.offset.mustNewConstMetric(resp.ClockOffset.Seconds())
	ch <- c.root_delay.mustNewConstMetric(resp.RootDelay.Seconds())
	ch <- c.root_dispersion.mustNewConstMetric(resp.RootDispersion.Seconds())

	var sanity float64
	if resp.Leap != ntp.LeapNotInSync &&
		0 < resp.Stratum && resp.Stratum < ntp.MaxStratum &&
		0 <= freshness && // from packet()
		freshness <= 24*time.Hour && // 24h is heuristics from ntpdate
		lambda <= maxDispersion*time.Second && // from packet()
		root_delay <= *ntpMaxDistance && // from fit()
		0 <= resp.RTT && // ensuring that clock tick forward
		-1*offset_margin <= resp.ClockOffset && resp.ClockOffset <= offset_margin {
		sanity = 1.
	}
	ch <- c.sanity.mustNewConstMetric(sanity)
	return nil
}
