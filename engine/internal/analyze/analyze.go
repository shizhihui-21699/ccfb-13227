package analyze

import (
	"sort"
	"strings"

	"solrecon/internal/sol"
)

type analyzer struct {
	prog      *Program
	findings  []Finding
	diags     []Diag
	fnFile    map[*sol.Func]*File
	fnIndex   map[string][]*sol.Func // "Contract.name" and "name"
	guardMods map[*sol.Contract]map[string]bool
}

// Analyze runs every rule over the given files and builds a report.
func Analyze(files []*File) *Report {
	p := NewProgram(files)
	return analyzeProgram(p)
}

func newAnalyzer(p *Program) *analyzer {
	return &analyzer{
		prog:      p,
		fnFile:    map[*sol.Func]*File{},
		fnIndex:   map[string][]*sol.Func{},
		guardMods: map[*sol.Contract]map[string]bool{},
	}
}

func analyzeProgram(p *Program) *Report {
	a := newAnalyzer(p)

	for _, f := range p.Files {
		for _, d := range f.AST.Diagnostics {
			a.diags = append(a.diags, Diag{File: f.Name, Line: d.Line, Col: d.Col, Msg: d.Msg})
		}
		for _, c := range f.AST.Contracts {
			guards := map[string]bool{}
			for _, m := range c.Members {
				switch mm := m.(type) {
				case *sol.Func:
					a.fnFile[mm] = f
					a.fnIndex[c.Name+"."+mm.Name] = append(a.fnIndex[c.Name+"."+mm.Name], mm)
					a.fnIndex[mm.Name] = append(a.fnIndex[mm.Name], mm)
					if mm.Kind == "modifier" && modifierLooksLikeGuard(mm) {
						guards[mm.Name] = true
					}
				}
			}
			a.guardMods[c] = guards
		}
		for _, f2 := range f.AST.Functions {
			a.fnFile[f2] = f
			a.fnIndex[f2.Name] = append(a.fnIndex[f2.Name], f2)
		}
	}

	for _, f := range p.Files {
		for _, c := range f.AST.Contracts {
			for _, m := range c.Members {
				if sv, ok := m.(*sol.StateVar); ok {
					a.checkStateVarInit(f, c, sv)
				}
			}
			a.checkContract(f, c)
		}
		for _, fn := range f.AST.Functions {
			ctx := newFnCtx(a, f, nil, fn)
			a.checkFunction(ctx)
		}
	}

	return a.report()
}

func (a *analyzer) report() *Report {
	r := &Report{Catalog: Catalog(), Files: []FileMeta{}}
	// Dedupe by rule + file + line + function. Column is deliberately ignored:
	// several matches on one source line are one issue to a reviewer.
	uniq := map[string]bool{}
	var out []Finding
	for _, f := range a.findings {
		k := f.Rule + "|" + f.File + "|" + itoa(f.Line) + "|" + f.Function
		if uniq[k] {
			continue
		}
		uniq[k] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if sevRank(out[i].Severity) != sevRank(out[j].Severity) {
			return sevRank(out[i].Severity) < sevRank(out[j].Severity)
		}
		return out[i].Line < out[j].Line
	})
	if out == nil {
		out = []Finding{}
	}
	r.Findings = out
	if a.diags == nil {
		a.diags = []Diag{}
	}
	r.Diagnostics = a.diags
	sum := Summary{BySev: map[string]int{}, ByCat: map[string]int{}}
	contracts := map[string]bool{}
	fns := 0
	for _, f := range a.prog.Files {
		r.Files = append(r.Files, FileMeta{
			Name:      f.Name,
			Pragma:    f.AST.Pragma,
			Lines:     len(f.Lines),
			Contracts: len(f.AST.Contracts),
			Functions: countFunctions(f.AST),
		})
		for _, c := range f.AST.Contracts {
			contracts[c.Name] = true
		}
		fns += countFunctions(f.AST)
	}
	for _, f := range out {
		sum.Total++
		sum.BySev[f.Severity]++
		sum.ByCat[f.Category]++
	}
	sum.Files = len(a.prog.Files)
	sum.Contracts = len(contracts)
	sum.Functions = fns
	r.Summary = sum
	r.Coverage = coverage()
	return r
}

func countFunctions(s *sol.Source) int {
	n := 0
	for _, c := range s.Contracts {
		for _, m := range c.Members {
			if _, ok := m.(*sol.Func); ok {
				n++
			}
		}
	}
	n += len(s.Functions)
	return n
}

func sevRank(s string) int {
	switch s {
	case SevHigh:
		return 0
	case SevMedium:
		return 1
	case SevLow:
		return 2
	}
	return 3
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ---- function context ----

type fnCtx struct {
	a        *analyzer
	file     *File
	contract *sol.Contract
	fn       *sol.Func
	state    map[string]*sol.StateVar
	consts   map[string]bool
	locals   map[string]string // name -> type (params + block locals)
	guard    bool
	guardWhy string
	// for ordering: call events pending within current straight-line region
	pending []pendingCall
	// diagnostics for current function
	inlineDepth int
	visited     map[*sol.Func]bool
}

type pendingCall struct {
	pos  sol.Pos
	kind string
	desc string
	fn   string
}

func newFnCtx(a *analyzer, f *File, c *sol.Contract, fn *sol.Func) *fnCtx {
	ctx := &fnCtx{
		a:        a,
		file:     f,
		contract: c,
		fn:       fn,
		state:    map[string]*sol.StateVar{},
		consts:   map[string]bool{},
		locals:   map[string]string{},
		visited:  map[*sol.Func]bool{},
	}
	if c != nil {
		for _, m := range c.Members {
			if sv, ok := m.(*sol.StateVar); ok {
				ctx.state[sv.Name] = sv
				if sv.Constant {
					ctx.consts[sv.Name] = true
				}
			}
		}
	}
	for _, p := range fn.Params {
		if p.Name != "" {
			ctx.locals[p.Name] = p.Type
		}
	}
	for _, p := range fn.Returns {
		if p.Name != "" {
			ctx.locals[p.Name] = p.Type
		}
	}
	ctx.guard, ctx.guardWhy = a.detectGuard(c, fn)
	return ctx
}

func (a *analyzer) checkContract(f *File, c *sol.Contract) {
	// interface / library bodies are not security-relevant for access rules,
	// but arithmetic inside libraries is.
	for _, m := range c.Members {
		fn, ok := m.(*sol.Func)
		if !ok || fn.Body == nil {
			continue
		}
		ctx := newFnCtx(a, f, c, fn)
		a.checkFunction(ctx)
	}
}

func (a *analyzer) checkStateVarInit(f *File, c *sol.Contract, sv *sol.StateVar) {
	if sv.Init == nil {
		return
	}
	ctx := &fnCtx{a: a, file: f, contract: c, state: map[string]*sol.StateVar{}, consts: map[string]bool{}, locals: map[string]string{}}
	for _, m := range c.Members {
		if s, ok := m.(*sol.StateVar); ok {
			ctx.state[s.Name] = s
		}
	}
	a.checkRandomnessExpr(ctx, sv.Init, "state variable "+sv.Name)
	a.checkIntegerExpr(ctx, sv.Init)
}

func (a *analyzer) checkFunction(ctx *fnCtx) {
	fn := ctx.fn
	if fn.Body == nil {
		return
	}
	if ctx.contract != nil {
		a.checkAccess(ctx)
	}
	a.checkReentrancy(ctx)
	a.checkUncheckedCalls(ctx)
	a.checkRandomness(ctx)
	a.checkIntegers(ctx)
}

// ---- finding emit ----

type findingOpts struct {
	rule, category, severity, title string
	pos                             sol.Pos
	endLine                         int
	message, exploit, fix           string
	confidence                      string
	relatedLine                     int
	relatedTag                      string
	tags                            []string
}

func (ctx *fnCtx) emit(o findingOpts) {
	name := ""
	file := ""
	if ctx.file != nil {
		file = ctx.file.Name
	}
	if ctx.contract != nil {
		name = ctx.contract.Name
	}
	fnName := ""
	if ctx.fn != nil {
		fnName = ctx.fn.Name
		if fnName == "" {
			fnName = ctx.fn.Kind
		}
	}
	snippet := ""
	if ctx.file != nil {
		snippet = snippetAt(ctx.file, o.pos.Line, o.endLine)
	}
	ctx.a.findings = append(ctx.a.findings, Finding{
		Rule:       o.rule,
		Category:   o.category,
		Severity:   o.severity,
		Title:      o.title,
		File:       file,
		Line:       o.pos.Line,
		Col:        o.pos.Col,
		EndLine:    o.endLine,
		Contract:   name,
		Function:   fnName,
		Message:    o.message,
		Exploit:    o.exploit,
		Fix:        o.fix,
		Snippet:    snippet,
		Confidence: o.confidence,
		Related:    o.relatedLine,
		RelatedTag: o.relatedTag,
		Tags:       o.tags,
	})
}

func snippetAt(f *File, line, endLine int) string {
	if f == nil || line < 1 || line > len(f.Lines) {
		return ""
	}
	if endLine <= 0 || endLine > len(f.Lines) {
		endLine = line
	}
	if endLine < line {
		endLine = line
	}
	if endLine-line > 6 {
		endLine = line + 6
	}
	return strings.Join(f.Lines[line-1:endLine], "\n")
}
