package sol_test

import (
	"os"
	"path/filepath"
	"testing"

	"solrecon/internal/analyze"
	"solrecon/internal/sol"
)

// TestParserCoverage parses a deliberately broad Solidity file and requires
// that the tolerant parser produces no diagnostics and recovers the expected
// declarations.
func TestParserCoverage(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "syntax", "Kitchen.sol")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	src := string(b)
	s := sol.Parse(src)

	for _, d := range s.Diagnostics {
		t.Errorf("unexpected diagnostic at %d:%d: %s", d.Line, d.Col, d.Msg)
	}

	got := map[string]string{}
	for _, c := range s.Contracts {
		got[c.Name] = c.Kind
	}
	want := map[string]string{
		"IOracle": "interface",
		"MathLib": "library",
		"Base":    "contract",
		"Kitchen": "contract",
	}
	for name, kind := range want {
		if got[name] != kind {
			t.Errorf("contract %s: got kind %q, want %q", name, got[name], kind)
		}
	}

	// find Kitchen and count its members by kind
	var kitchen *sol.Contract
	for _, c := range s.Contracts {
		if c.Name == "Kitchen" {
			kitchen = c
		}
	}
	if kitchen == nil {
		t.Fatal("Kitchen not parsed")
	}
	kinds := map[string]int{}
	funcs := map[string]*sol.Func{}
	for _, m := range kitchen.Members {
		switch x := m.(type) {
		case *sol.Func:
			kinds["func"]++
			funcs[x.Name] = x
		case *sol.StateVar:
			kinds["var"]++
		case *sol.StructDef:
			kinds["struct"]++
		case *sol.EnumDef:
			kinds["enum"]++
		case *sol.EventDef:
			kinds["event"]++
		case *sol.ErrorDef:
			kinds["error"]++
		}
	}
	if kinds["struct"] != 1 || kinds["enum"] != 1 {
		t.Errorf("member kinds = %v, want one struct and one enum", kinds)
	}
	// event/error are declared on Base in the fixture
	var base *sol.Contract
	for _, c := range s.Contracts {
		if c.Name == "Base" {
			base = c
		}
	}
	if base == nil {
		t.Fatal("Base not parsed")
	}
	var bevents, berrors int
	for _, m := range base.Members {
		switch m.(type) {
		case *sol.EventDef:
			bevents++
		case *sol.ErrorDef:
			berrors++
		}
	}
	if bevents != 1 || berrors != 1 {
		t.Errorf("Base: events=%d errors=%d, want 1/1", bevents, berrors)
	}
	for _, name := range []string{"open", "readOracle", "safeRead", "loops", "asm", "payableFlow", "tup", "_check"} {
		if funcs[name] == nil {
			t.Errorf("function %q not parsed", name)
		} else if funcs[name].Body == nil {
			t.Errorf("function %q has no body", name)
		}
	}
	if fn := funcs["open"]; fn != nil && len(fn.Returns) != 1 {
		t.Errorf("open: returns = %d, want 1", len(fn.Returns))
	}
	if fn := funcs["open"]; fn != nil {
		if len(fn.Modifiers) != 1 || fn.Modifiers[0].Name != "onlyActive" {
			t.Errorf("open: modifiers = %+v, want onlyActive", fn.Modifiers)
		}
	}
}

// TestParserTolerant checks that broken syntax degrades instead of failing the
// whole file: findings from the intact part must survive.
func TestParserTolerant(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Broken {
    function fine() external { uint256 x = ; }
    function ok(address payable to) external {
        to.call{value: 1}("");
    }
    this is not solidity at all @@@
}
`
	s := sol.Parse(src)
	if len(s.Contracts) == 0 {
		t.Fatal("contract not recovered from broken source")
	}
	var f bool
	for _, c := range s.Contracts {
		for _, m := range c.Members {
			if fn, ok := m.(*sol.Func); ok && fn.Name == "ok" {
				f = true
			}
		}
	}
	if !f {
		t.Error("intact function after a broken one was not recovered")
	}

	files := []*analyze.File{{
		Name:  "Broken.sol",
		Src:   src,
		Lines: splitLines(src),
		AST:   s,
	}}
	rep := analyze.Analyze(files)
	found := false
	for _, fd := range rep.Findings {
		if fd.Rule == "UNCHK-01" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected UNCHK-01 from intact function despite syntax errors; findings: %+v, diags: %+v", rep.Findings, rep.Diagnostics)
	}
	if len(rep.Diagnostics) == 0 {
		t.Error("expected a diagnostic for the broken syntax")
	}
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}
