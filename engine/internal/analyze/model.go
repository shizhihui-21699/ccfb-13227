package analyze

import (
	"strings"

	"solrecon/internal/sol"
)

// Severity levels, ordered most severe first.
const (
	SevHigh   = "high"
	SevMedium = "medium"
	SevLow    = "low"
	SevInfo   = "info"
)

// Categories map to the five audit questions the tool answers.
const (
	CatReentrancy = "reentrancy"
	CatUnchecked  = "unchecked-call"
	CatAccess     = "access-control"
	CatRandom     = "randomness"
	CatInteger    = "integer"
)

// Finding is one issue anchored to a source line.
type Finding struct {
	Rule       string   `json:"rule"`
	Category   string   `json:"category"`
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Col        int      `json:"col"`
	EndLine    int      `json:"endLine"`
	Contract   string   `json:"contract"`
	Function   string   `json:"function"`
	Message    string   `json:"message"`
	Exploit    string   `json:"exploit"`
	Fix        string   `json:"fix"`
	Snippet    string   `json:"snippet"`
	Related    int      `json:"relatedLine,omitempty"`
	RelatedTag string   `json:"relatedTag,omitempty"`
	Confidence string   `json:"confidence"`
	Tags       []string `json:"tags,omitempty"`
}

// File is one parsed source unit.
type File struct {
	Name     string
	Src      string
	Lines    []string
	AST      *sol.Source
	Pragma   [3]int // major, minor, patch of the lowest bound mentioned
	PragmaOK bool
}

// Program is the whole audit target: one or more files.
type Program struct {
	Files      []*File
	Contracts  map[string]*sol.Contract
	Libraries  map[string]bool
	Interfaces map[string]bool
	// contract -> set of modifier names that look like reentrancy guards
	guards map[*sol.Contract]map[string]bool
}

// Report is the analyzer output.
type Report struct {
	Findings    []Finding  `json:"findings"`
	Diagnostics []Diag     `json:"diagnostics"`
	Summary     Summary    `json:"summary"`
	Coverage    Coverage   `json:"coverage"`
	Files       []FileMeta `json:"files"`
	Catalog     []RuleMeta `json:"catalog"`
}

type Diag struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Col  int    `json:"col"`
	Msg  string `json:"message"`
}

type FileMeta struct {
	Name      string `json:"name"`
	Pragma    string `json:"pragma"`
	Lines     int    `json:"lines"`
	Contracts int    `json:"contracts"`
	Functions int    `json:"functions"`
}

type Summary struct {
	Total     int            `json:"total"`
	BySev     map[string]int `json:"bySeverity"`
	ByCat     map[string]int `json:"byCategory"`
	Files     int            `json:"files"`
	Contracts int            `json:"contracts"`
	Functions int            `json:"functions"`
}

type Coverage struct {
	Supported  []string `json:"supported"`
	Partial    []string `json:"partial"`
	NotCovered []string `json:"notCovered"`
}

type RuleMeta struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Severity string `json:"defaultSeverity"`
	Title    string `json:"title"`
	Summary  string `json:"summary"`
	How      string `json:"how"`
}

// NewProgram indexes parsed files.
func NewProgram(files []*File) *Program {
	p := &Program{
		Files:      files,
		Contracts:  map[string]*sol.Contract{},
		Libraries:  map[string]bool{},
		Interfaces: map[string]bool{},
		guards:     map[*sol.Contract]map[string]bool{},
	}
	for _, f := range files {
		for _, c := range f.AST.Contracts {
			if c.Name == "" {
				continue
			}
			// first definition wins; later duplicates keep earlier one
			if _, ok := p.Contracts[c.Name]; !ok {
				p.Contracts[c.Name] = c
			}
			switch c.Kind {
			case "library":
				p.Libraries[c.Name] = true
			case "interface":
				p.Interfaces[c.Name] = true
			}
		}
	}
	for _, c := range p.Contracts {
		p.guards[c] = map[string]bool{}
		for _, m := range c.Members {
			fn, ok := m.(*sol.Func)
			if !ok {
				continue
			}
			if fn.Kind == "modifier" && looksLikeGuard(fn.Name) {
				p.guards[c][fn.Name] = true
			}
		}
	}
	return p
}

func looksLikeGuard(name string) bool {
	n := strings.ToLower(name)
	for _, k := range []string{"nonreentrant", "noreentrant", "reentrancyguard", "mutex", "lock", "nested", "once"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}
