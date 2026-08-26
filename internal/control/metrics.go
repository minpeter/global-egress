package control

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/minpeter/global-egress/internal/pool"
)

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetrics(w, s.opts.Pool.Metrics())
}

func writeMetrics(w http.ResponseWriter, snapshot pool.MetricsSnapshot) {
	writeMetricHeader(w,
		"global_egress_request_results_total",
		"counter",
		"Completed proxy requests by result, selected country, and entry.",
	)
	for _, metric := range snapshot.Requests {
		fmt.Fprintf(w,
			"global_egress_request_results_total{result=%s,country=%s,entry=%s} %d\n",
			label(string(metric.Result)), label(metric.Country), label(metric.Entry), metric.Count)
	}

	writeMetricHeader(w,
		"global_egress_request_duration_seconds",
		"histogram",
		"Request setup duration until upstream readiness.",
	)
	for _, metric := range snapshot.RequestDurations {
		labels := fmt.Sprintf("result=%s,country=%s,entry=%s",
			label(string(metric.Result)), label(metric.Country), label(metric.Entry))
		for _, bucket := range metric.Buckets {
			fmt.Fprintf(w,
				"global_egress_request_duration_seconds_bucket{%s,le=%s} %d\n",
				labels, label(bucket.UpperBound), bucket.Count)
		}
		fmt.Fprintf(w, "global_egress_request_duration_seconds_sum{%s} %s\n",
			labels, float(metric.Sum))
		fmt.Fprintf(w, "global_egress_request_duration_seconds_count{%s} %d\n",
			labels, metric.Count)
	}

	writeMetricHeader(w,
		"global_egress_request_timeouts_total",
		"counter",
		"Timed-out proxy requests by phase, selected country, and entry.",
	)
	for _, metric := range snapshot.RequestTimeouts {
		fmt.Fprintf(w,
			"global_egress_request_timeouts_total{phase=%s,country=%s,entry=%s} %d\n",
			label(string(metric.Phase)), label(metric.Country), label(metric.Entry), metric.Count)
	}

	writeMetricHeader(w,
		"global_egress_entry_state",
		"gauge",
		"Entry tunnels currently in each rotation state.",
	)
	for _, metric := range snapshot.EntryStates {
		fmt.Fprintf(w, "global_egress_entry_state{state=%s} %d\n",
			label(string(metric.State)), metric.Count)
	}

	writeMetricHeader(w,
		"global_egress_entry_failures_total",
		"counter",
		"Entry tunnel failures by reason.",
	)
	for _, metric := range snapshot.EntryFailures {
		fmt.Fprintf(w, "global_egress_entry_failures_total{reason=%s} %d\n",
			label(string(metric.Reason)), metric.Count)
	}

	writeMetricHeader(w,
		"global_egress_requested_country_total",
		"counter",
		"Proxy requests by requested country policy.",
	)
	writeCountryMetrics(w, "global_egress_requested_country_total", snapshot.RequestedCountries)
	writeMetricHeader(w,
		"global_egress_selected_country_total",
		"counter",
		"Proxy requests by selected exit country.",
	)
	writeCountryMetrics(w, "global_egress_selected_country_total", snapshot.SelectedCountries)

	writeMetricHeader(w,
		"global_egress_country_fallback_total",
		"counter",
		"Requests whose selected exit country differed from the requested country.",
	)
	for _, metric := range snapshot.CountryFallbacks {
		fmt.Fprintf(w,
			"global_egress_country_fallback_total{requested=%s,selected=%s} %d\n",
			label(metric.Requested), label(metric.Selected), metric.Count)
	}

	writeMetricHeader(w,
		"global_egress_payload_bytes_total",
		"counter",
		"Relayed payload bytes by direction, selected country, and entry.",
	)
	for _, metric := range snapshot.Payloads {
		labels := fmt.Sprintf("country=%s,entry=%s", label(metric.Country), label(metric.Entry))
		fmt.Fprintf(w,
			"global_egress_payload_bytes_total{direction=\"sent\",%s} %d\n",
			labels, metric.Sent)
		fmt.Fprintf(w,
			"global_egress_payload_bytes_total{direction=\"received\",%s} %d\n",
			labels, metric.Received)
	}

	writeMetricHeader(w,
		"global_egress_tunnel_opens_total",
		"counter",
		"WireGuard tunnel open attempts by role and result.",
	)
	for _, metric := range snapshot.TunnelOpens {
		fmt.Fprintf(w,
			"global_egress_tunnel_opens_total{role=%s,result=%s} %d\n",
			label(string(metric.Role)), label(string(metric.Result)), metric.Count)
	}

	writeMetricHeader(w,
		"global_egress_tunnel_open_duration_seconds",
		"histogram",
		"WireGuard tunnel setup and handshake duration.",
	)
	for _, metric := range snapshot.TunnelDurations {
		labels := fmt.Sprintf("role=%s,result=%s",
			label(string(metric.Role)), label(string(metric.Result)))
		for _, bucket := range metric.Buckets {
			fmt.Fprintf(w,
				"global_egress_tunnel_open_duration_seconds_bucket{%s,le=%s} %d\n",
				labels, label(bucket.UpperBound), bucket.Count)
		}
		fmt.Fprintf(w, "global_egress_tunnel_open_duration_seconds_sum{%s} %s\n",
			labels, float(metric.Sum))
		fmt.Fprintf(w, "global_egress_tunnel_open_duration_seconds_count{%s} %d\n",
			labels, metric.Count)
	}
}

func writeCountryMetrics(w http.ResponseWriter, name string, metrics []pool.CountryMetric) {
	for _, metric := range metrics {
		fmt.Fprintf(w, "%s{country=%s} %d\n", name, label(metric.Country), metric.Count)
	}
}

func writeMetricHeader(w http.ResponseWriter, name, metricType, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func label(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func float(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}
