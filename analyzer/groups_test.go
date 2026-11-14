package analyzer

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/output"
	"github.com/olelbis/tlsanalyzer/policy"
)

func groupServer(t *testing.T, curves ...tls.CurveID) (host, port string) {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: curves}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	return host, port
}

func groupNames(result Result) string {
	for _, r := range result.Results {
		if r.VersionID == tls.VersionTLS13 {
			names := make([]string, len(r.KeyExchangeGroups))
			for i, g := range r.KeyExchangeGroups {
				names[i] = g.Name
			}
			return strings.Join(names, ",")
		}
	}
	return ""
}

func TestRunEnumeratesKeyExchangeGroupsOnlyWhenAsked(t *testing.T) {
	host, port := groupServer(t, tls.X25519MLKEM768, tls.X25519)

	plain, err := Run(scanRangeOptions(host, port, tls.VersionTLS13, policy.Config{}), Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := groupNames(plain); got != "" {
		t.Fatalf("groups = %q without --enum-groups, want none (no extra connections for those who did not ask)", got)
	}

	opts := scanRangeOptions(host, port, tls.VersionTLS13, policy.Config{})
	opts.EnumGroups = true
	enumerated, err := Run(opts, Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	got := groupNames(enumerated)
	if !strings.Contains(got, "X25519MLKEM768") || !strings.Contains(got, "X25519") {
		t.Fatalf("groups = %q, want X25519MLKEM768 and X25519", got)
	}
	if enumerated.Policy.Enabled {
		t.Fatalf("Policy = %+v, enumerating groups alone must not enable a policy", enumerated.Policy)
	}
}

func TestRunRequirePostQuantumImpliesEnumerationAndJudgesTheEndpoint(t *testing.T) {
	config := policy.Config{RequirePostQuantum: true}

	t.Run("hybrid endpoint passes", func(t *testing.T) {
		host, port := groupServer(t, tls.X25519MLKEM768, tls.X25519)
		result, err := Run(scanRangeOptions(host, port, tls.VersionTLS13, config), Hooks{})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Policy.Passed {
			t.Fatalf("Failures = %+v, want --require-pq to pass on an endpoint that accepts X25519MLKEM768", result.Policy.Failures)
		}
	})

	t.Run("classical endpoint fails", func(t *testing.T) {
		host, port := groupServer(t, tls.X25519, tls.CurveP256)
		result, err := Run(scanRangeOptions(host, port, tls.VersionTLS13, config), Hooks{})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if result.Policy.Passed || len(result.Policy.Failures) != 1 || result.Policy.Failures[0].Check != policy.CheckRequirePQ {
			t.Fatalf("Policy = %+v, want one %s failure", result.Policy, policy.CheckRequirePQ)
		}
		if got := groupNames(result); !strings.Contains(got, "X25519") || strings.Contains(got, "MLKEM") {
			t.Fatalf("groups = %q, want the classical groups the endpoint accepts", got)
		}
	})
}

func TestRunWithBaselineFailsWhenPostQuantumGroupIsLost(t *testing.T) {
	hybridHost, hybridPort := groupServer(t, tls.X25519MLKEM768, tls.X25519)
	opts := scanRangeOptions(hybridHost, hybridPort, tls.VersionTLS13, policy.Config{})
	opts.EnumGroups = true
	recorded, err := Run(opts, Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	base := output.NewJSONReport(hybridHost, hybridPort, "", "test", time.Now(), recorded.Results)

	// The same endpoint after a downgrade of its TLS library.
	host, port := groupServer(t, tls.X25519)
	current := scanRangeOptions(host, port, tls.VersionTLS13, policy.Config{})
	current.Baseline = &base
	result, err := Run(current, Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Policy.Passed {
		t.Fatal("the baseline gate passed although the post-quantum group was lost")
	}
	found := false
	for _, failure := range result.Policy.Failures {
		if failure.Check == policy.CheckBaseline && strings.Contains(failure.Message, "no longer accepts post-quantum key exchange group X25519MLKEM768") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Failures = %+v, want a baseline failure naming X25519MLKEM768 (groups were enumerated because the baseline lists them)", result.Policy.Failures)
	}
}
