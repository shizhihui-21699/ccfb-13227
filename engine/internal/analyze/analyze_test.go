package analyze_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"solrecon/internal/analyze"
	"solrecon/internal/sol"
)

func load(t *testing.T, paths ...string) []*analyze.File {
	t.Helper()
	var out []*analyze.File
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		src := string(b)
		out = append(out, &analyze.File{
			Name:  filepath.Base(p),
			Src:   src,
			Lines: strings.Split(src, "\n"),
			AST:   sol.Parse(src),
		})
	}
	return out
}

func rulesAt(rep *analyze.Report) map[string]int {
	m := map[string]int{}
	for _, f := range rep.Findings {
		m[f.Rule]++
	}
	return m
}

type expectation struct {
	file    string
	rule    string
	line    int
	present bool
}

func TestSamplePairs(t *testing.T) {
	root := filepath.Join("..", "..", "..", "samples")
	type tc struct {
		name string
		dir  string
		// rules that MUST be present in the vulnerable version
		wantVuln []string
		// rules that must NOT be present in the fixed version
		forbidFixed []string
		// exact line checks in the vulnerable version
		lines []expectation
	}
	cases := []tc{
		{
			name:        "reentrancy",
			dir:         "01-reentrancy",
			wantVuln:    []string{"REENT-01", "UNCHK-01", "UNCHK-02"},
			forbidFixed: []string{"REENT-01", "UNCHK-01", "UNCHK-02", "ACCESS-01"},
			lines: []expectation{
				{"Bank.sol", "REENT-01", 17, true}, // withdraw: call to msg.sender
				{"Bank.sol", "REENT-01", 24, true}, // payout: call before balances[to] = 0
			},
		},
		{
			name:     "unchecked",
			dir:      "02-unchecked",
			wantVuln: []string{"UNCHK-01", "UNCHK-02", "REENT-01"},
			// the fixed sample reorders effects before interactions, so even
			// the reentrancy rule must stay quiet
			forbidFixed: []string{"UNCHK-01", "UNCHK-02", "REENT-01"},
			lines: []expectation{
				{"Distributor.sol", "UNCHK-01", 16, true},
				{"Distributor.sol", "UNCHK-01", 22, true},
			},
		},
		{
			name:        "access",
			dir:         "03-access",
			wantVuln:    []string{"ACCESS-01"},
			forbidFixed: []string{"ACCESS-01"},
			lines: []expectation{
				{"Vault.sol", "ACCESS-01", 20, true}, // setFeeRecipient
				{"Vault.sol", "ACCESS-01", 25, true}, // setOracle
				{"Vault.sol", "ACCESS-01", 30, true}, // setPaused
			},
		},
		{
			name:     "randomness",
			dir:      "04-randomness",
			wantVuln: []string{"RAND-01"},
			// the fixed version still times the reveal window with
			// block.timestamp; that is not randomness, so nothing may fire
			forbidFixed: []string{"RAND-01"},
			lines: []expectation{
				{"Lottery.sol", "RAND-01", 18, true},
				{"Lottery.sol", "RAND-01", 26, true},
				{"Lottery.sol", "RAND-01", 34, true},
			},
		},
		{
			name:        "integer",
			dir:         "05-integer",
			wantVuln:    []string{"INT-01", "INT-02", "ACCESS-01"},
			forbidFixed: []string{"INT-01", "INT-02"},
			lines: []expectation{
				{"Token.sol", "INT-01", 12, true}, // totalSupply + amount (0.7)
				{"Token.sol", "INT-01", 18, true}, // balances - amount underflow
				{"Token.sol", "INT-02", 25, true}, // uint96(r)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vulnDir := filepath.Join(root, c.dir, "vulnerable")
			fixedDir := filepath.Join(root, c.dir, "fixed")
			vs, _ := filepath.Glob(filepath.Join(vulnDir, "*.sol"))
			fs, _ := filepath.Glob(filepath.Join(fixedDir, "*.sol"))
			if len(vs) == 0 || len(fs) == 0 {
				t.Fatalf("missing sample files under %s", filepath.Join(root, c.dir))
			}

			vr := analyze.Analyze(load(t, vs...))
			have := rulesAt(vr)
			for _, want := range c.wantVuln {
				if have[want] == 0 {
					t.Errorf("vulnerable sample: rule %s not reported; got %v", want, sortedKeys(have))
				}
			}

			// line-level assertions
			for _, exp := range c.lines {
				found := false
				for _, f := range vr.Findings {
					if f.Rule == exp.rule && f.File == exp.file && f.Line == exp.line {
						found = true
						break
					}
				}
				if found != exp.present {
					t.Errorf("%s:%d rule %s present=%v, want %v (findings: %s)",
						exp.file, exp.line, exp.rule, found, exp.present, describe(vr))
				}
				// every finding must carry a usable explanation
				for _, f := range vr.Findings {
					if f.Exploit == "" || f.Fix == "" || f.Message == "" {
						t.Errorf("finding %s %s:%d missing exploit/fix text", f.Rule, f.File, f.Line)
					}
				}
			}

			fr := analyze.Analyze(load(t, fs...))
			fhave := rulesAt(fr)
			for _, forbid := range c.forbidFixed {
				if fhave[forbid] > 0 {
					t.Errorf("fixed sample: rule %s should not fire; findings: %s", forbid, describe(fr))
				}
			}
		})
	}
}

func sortedKeys(m map[string]int) []string {
	var out []string
	for k, v := range m {
		if v > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func describe(r *analyze.Report) string {
	var parts []string
	for _, f := range r.Findings {
		parts = append(parts, f.Rule+"@"+f.File+":"+itoa(f.Line))
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
