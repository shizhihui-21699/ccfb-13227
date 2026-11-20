package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"solrecon/internal/analyze"
	"solrecon/internal/sol"
)

func main() {
	jsonOut := flag.Bool("json", false, "emit JSON report")
	sevMin := flag.String("min", "info", "minimum severity to print: high|medium|low|info")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: auditcli [-json] [-min sev] file.sol...")
		os.Exit(2)
	}
	var files []*analyze.File
	// File names must be unique within one run: the vulnerable and fixed
	// samples share a basename, and the report is keyed by name. Use the path
	// as given on the command line.
	used := map[string]int{}
	for _, a := range args {
		paths := []string{a}
		if st, err := os.Stat(a); err == nil && st.IsDir() {
			paths = nil
			filepath.Walk(a, func(p string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() && strings.HasSuffix(p, ".sol") {
					paths = append(paths, p)
				}
				return nil
			})
			sort.Strings(paths)
		}
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read %s: %v\n", p, err)
				os.Exit(1)
			}
			name := p
			used[name]++
			if used[name] > 1 {
				name = fmt.Sprintf("%s#%d", p, used[name])
			}
			src := string(b)
			files = append(files, &analyze.File{
				Name:  name,
				Src:   src,
				Lines: strings.Split(src, "\n"),
				AST:   sol.Parse(src),
			})
		}
	}
	rep := analyze.Analyze(files)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
		return
	}
	printReport(rep, *sevMin)
}

func rank(s string) int {
	switch s {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	}
	return 3
}

func printReport(r *analyze.Report, min string) {
	fmt.Printf("\n\x1b[1mSolRecon\x1b[0m  %d files · %d contracts · %d functions\n", r.Summary.Files, r.Summary.Contracts, r.Summary.Functions)
	fmt.Printf("findings: %d  (high %d, medium %d, low %d, info %d)\n\n",
		r.Summary.Total, r.Summary.BySev["high"], r.Summary.BySev["medium"], r.Summary.BySev["low"], r.Summary.BySev["info"])
	shown := 0
	for _, f := range r.Findings {
		if rank(f.Severity) > rank(min) {
			continue
		}
		shown++
		color := "\x1b[31m"
		switch f.Severity {
		case "medium":
			color = "\x1b[33m"
		case "low":
			color = "\x1b[36m"
		case "info":
			color = "\x1b[90m"
		}
		fmt.Printf("%s%-6s\x1b[0m %s  %s:%d  \x1b[1m%s\x1b[0m\n", color, strings.ToUpper(f.Severity), f.Rule, f.File, f.Line, f.Title)
		fmt.Printf("       %s · %s\n", f.Contract, f.Function)
		fmt.Printf("       %s\n\n", f.Message)
	}
	if shown == 0 {
		fmt.Println("no findings at or above the requested severity")
	}
	if len(r.Diagnostics) > 0 {
		fmt.Printf("parse diagnostics: %d\n", len(r.Diagnostics))
		for i, d := range r.Diagnostics {
			if i >= 10 {
				fmt.Printf("  ... %d more\n", len(r.Diagnostics)-10)
				break
			}
			fmt.Printf("  %s:%d:%d  %s\n", d.File, d.Line, d.Col, d.Msg)
		}
	}
}
