package archtest

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// The alert rules, the SLO rules and the dashboard name metrics by string: a renamed or removed metric would leave an alert that
// never fires and a panel that stays empty, silently. Every relayplane_* series they query must be one the code registers.
func TestDashboardsAndRulesOnlyUseExportedMetrics(t *testing.T) {
	src := readRepoFile(t, "internal", "observability", "metrics.go")
	exported := map[string]bool{}
	for _, m := range regexp.MustCompile(`Name:\s*"(relayplane_[a-z0-9_]+)"`).FindAllStringSubmatch(src, -1) {
		exported[m[1]] = true
	}
	if len(exported) < 30 {
		t.Fatalf("found only %d metrics in metrics.go: the pattern no longer matches the code", len(exported))
	}
	dash := readRepoFile(t, "deploy", "grafana", "relayplane.json")
	if !json.Valid([]byte(dash)) {
		t.Fatal("deploy/grafana/relayplane.json is not valid JSON")
	}
	series := regexp.MustCompile(`\brelayplane_[a-z0-9_]+`)
	for _, f := range [][]string{{"deploy", "prometheus", "alerts.yml"}, {"deploy", "prometheus", "slo.yml"}, {"deploy", "prometheus", "slo_test.yml"}, {"deploy", "grafana", "relayplane.json"}} {
		for _, name := range series.FindAllString(readRepoFile(t, f...), -1) {
			base := name
			for _, suf := range []string{"_bucket", "_count", "_sum"} {
				if strings.HasSuffix(base, suf) && exported[strings.TrimSuffix(base, suf)] {
					base = strings.TrimSuffix(base, suf)
				}
			}
			if !exported[base] {
				t.Errorf("%s queries %s, which the code does not export", strings.Join(f, "/"), name)
			}
		}
	}
}
