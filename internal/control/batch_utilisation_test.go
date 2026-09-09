package control

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minpeter/global-egress/internal/pool"
)

// A unique batch remembers every exit IP it has burned for the whole batch TTL,
// which production now runs at 6h. Once the burned set approaches the pool size
// the next request can only fall through to the bounded no-uniq reuse path, so
// the ratio has to be scrapeable BEFORE it bites rather than inferred from a
// failure. Zero-initialised like EntryStates, so the series never disappears
// just because no batch is currently live.
func TestBatchUtilisationMetricsAlwaysPresent(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeMetrics(recorder, pool.MetricsSnapshot{})
	body := recorder.Body.String()

	for _, want := range []string{
		"# TYPE global_egress_unique_batches gauge",
		"global_egress_unique_batches 0",
		"# TYPE global_egress_batch_burned_exits gauge",
		"global_egress_batch_burned_exits 0",
		"# TYPE global_egress_batch_selectable_exits gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\nbody:\n%s", want, body)
		}
	}
}

// The gauges must carry the real numbers, not just exist.
func TestBatchUtilisationMetricsReportSnapshot(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeMetrics(recorder, pool.MetricsSnapshot{
		UniqueBatches:        3,
		BatchBurnedExits:     412,
		BatchSelectableExits: 127,
	})
	body := recorder.Body.String()

	for _, want := range []string{
		"global_egress_unique_batches 3",
		"global_egress_batch_burned_exits 412",
		"global_egress_batch_selectable_exits 127",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\nbody:\n%s", want, body)
		}
	}
}
