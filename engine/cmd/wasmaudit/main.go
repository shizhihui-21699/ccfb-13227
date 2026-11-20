//go:build js && wasm

package main

import (
	"encoding/json"
	"strings"
	"syscall/js"

	"solrecon/internal/analyze"
	"solrecon/internal/sol"
)

// The wasm module exposes one function on the global object:
//
//   solrecon.analyze(jsonPayload) -> jsonReport
//
// where payload is {"files":[{"name":"A.sol","src":"..."}]}.

func main() {
	js.Global().Set("solrecon", js.ValueOf(map[string]any{
		"analyze": js.FuncOf(analyzeFn),
		"version": js.ValueOf("1.0.0"),
	}))
	// keep the module alive
	select {}
}

type payload struct {
	Files []struct {
		Name string `json:"name"`
		Src  string `json:"src"`
	} `json:"files"`
}

func analyzeFn(this js.Value, args []js.Value) (out any) {
	defer func() {
		if r := recover(); r != nil {
			b, _ := json.Marshal(map[string]any{
				"error": "内部错误: " + toString(r),
			})
			out = string(b)
		}
	}()
	if len(args) < 1 {
		b, _ := json.Marshal(map[string]any{"error": "缺少输入"})
		return string(b)
	}
	raw := args[0].String()
	var p payload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		b, _ := json.Marshal(map[string]any{"error": "无法解析输入: " + err.Error()})
		return string(b)
	}
	var files []*analyze.File
	for _, f := range p.Files {
		name := f.Name
		if name == "" {
			name = "input.sol"
		}
		files = append(files, &analyze.File{
			Name:  name,
			Src:   f.Src,
			Lines: splitLines(f.Src),
			AST:   sol.Parse(f.Src),
		})
	}
	rep := analyze.Analyze(files)
	b, err := json.Marshal(rep)
	if err != nil {
		eb, _ := json.Marshal(map[string]any{"error": err.Error()})
		return string(eb)
	}
	return string(b)
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

// The report's snippet field is truncated for display convenience; the page
// renders its own snippet from the real source, so keep it short here.
func init() {}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return ""
}
