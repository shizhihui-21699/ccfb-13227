package sol

import (
	"fmt"
	"strings"
)

type parser struct {
	toks  []token
	i     int
	diags []Diag
	src   []rune
}

// Parse parses one Solidity source file. It is deliberately tolerant: unknown
// constructs are skipped and recorded as diagnostics rather than aborting, so a
// file written against a newer compiler still yields useful findings.
func Parse(src string) *Source {
	p := &parser{src: []rune(src)}
	var lexDiags []Diag
	p.toks, lexDiags = tokenize(src)
	p.diags = append(p.diags, lexDiags...)
	s := &Source{Diagnostics: p.diags}
	p.parseFile(s)
	s.Diagnostics = p.diags
	return s
}

func (p *parser) tok() token { return p.toks[p.i] }
func (p *parser) peekN(n int) token {
	if p.i+n >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[p.i+n]
}
func (p *parser) at(text string) bool { return p.tok().text == text }
func (p *parser) advance() token {
	t := p.toks[p.i]
	if p.i < len(p.toks)-1 {
		p.i++
	}
	return t
}
func (p *parser) accept(text string) bool {
	if p.at(text) {
		p.advance()
		return true
	}
	return false
}
func (p *parser) expect(text string) bool {
	if p.accept(text) {
		return true
	}
	p.diagf(p.tok().pos, "expected %q, found %q", text, p.tok().text)
	return false
}
func (p *parser) diagf(pos Pos, f string, a ...any) {
	if len(p.diags) > 400 {
		return
	}
	msg := sprintf(f, a...)
	p.diags = append(p.diags, Diag{Line: pos.Line, Col: pos.Col, Msg: msg})
}

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

// errorRecover skips to the next statement-ish boundary.
func (p *parser) recover(topLevel bool) {
	depth := 0
	for p.tok().kind != tEOF {
		t := p.tok().text
		if t == "{" || t == "(" || t == "[" {
			depth++
		} else if t == "}" || t == ")" || t == "]" {
			if depth == 0 {
				if t == "}" && !topLevel {
					return
				}
				if t == "}" {
					return
				}
			}
			depth--
		} else if depth == 0 && t == ";" {
			p.advance()
			return
		}
		p.advance()
	}
}

var reservedSkip = map[string]bool{
	"pragma": true, "import": true,
}

func (p *parser) parseFile(s *Source) {
	for p.tok().kind != tEOF {
		start := p.i
		switch {
		case p.at("pragma"):
			p.advance()
			var parts []string
			for p.tok().kind != tEOF && !p.at(";") {
				parts = append(parts, p.advance().text)
			}
			p.accept(";")
			s.Pragma = strings.Join(parts, " ")
			s.PragmaLine = p.toks[start].pos.Line
		case p.at("import"):
			p.advance()
			for p.tok().kind != tEOF && !p.at(";") {
				if p.tok().kind == tString {
					s.Imports = append(s.Imports, p.tok().text)
				}
				p.advance()
			}
			p.accept(";")
		case p.at("abstract") && p.peekN(1).text == "contract":
			p.advance()
			p.advance() // the `contract` keyword
			c := p.parseContract("contract")
			c.Abstract = true
			s.Contracts = append(s.Contracts, c)
		case p.at("contract") || p.at("interface") || p.at("library"):
			kind := p.advance().text
			s.Contracts = append(s.Contracts, p.parseContract(kind))
		case p.at("function"):
			f := p.parseFunction("function")
			s.Functions = append(s.Functions, f)
		case p.at("struct"):
			p.skipDeclaration()
		case p.at(";"):
			p.advance()
		default:
			p.diagf(p.tok().pos, "unexpected token %q at top level", p.tok().text)
			p.advance()
			if p.i == start {
				p.advance()
			}
		}
		if p.i == start {
			p.advance()
		}
	}
}

func (p *parser) skipDeclaration() {
	depth := 0
	for p.tok().kind != tEOF {
		t := p.tok().text
		if t == "{" {
			depth++
		} else if t == "}" {
			depth--
			p.advance()
			if depth <= 0 {
				return
			}
			continue
		} else if t == ";" && depth == 0 {
			p.advance()
			return
		}
		p.advance()
	}
}

func (p *parser) parseContract(kind string) *Contract {
	c := &Contract{Kind: kind, Pos: p.tok().pos}
	if p.tok().kind == tIdent {
		c.Name = p.advance().text
	} else {
		p.diagf(p.tok().pos, "expected contract name")
	}
	if p.accept("is") {
		for {
			if p.tok().kind == tIdent {
				name := p.advance().text
				// qualified name A.B
				for p.at(".") && p.peekN(1).kind == tIdent {
					p.advance()
					name = p.advance().text
				}
				c.Bases = append(c.Bases, name)
				if p.accept("(") {
					p.skipParens()
				}
			} else {
				break
			}
			if !p.accept(",") {
				break
			}
		}
	}
	// layout / other modifiers before body
	for p.tok().kind != tEOF && !p.at("{") && !p.at(";") {
		p.advance()
	}
	if !p.expect("{") {
		p.recover(true)
		return c
	}
	for p.tok().kind != tEOF && !p.at("}") {
		start := p.i
		m := p.parseContractMember(c)
		if m != nil {
			c.Members = append(c.Members, m)
		}
		if p.i == start {
			p.advance()
		}
	}
	p.accept("}")
	return c
}

// skipParens skips a parenthesised group. It accepts being called either at
// the opening "(" (which it consumes) or just after it.
func (p *parser) skipParens() {
	depth := 1
	if p.at("(") {
		p.advance()
	}
	for p.tok().kind != tEOF && depth > 0 {
		t := p.tok().text
		if t == "(" {
			depth++
		} else if t == ")" {
			depth--
			if depth == 0 {
				p.advance()
				return
			}
		}
		p.advance()
	}
}

func (p *parser) parseContractMember(c *Contract) Member {
	switch {
	case p.at("function"):
		return p.parseFunctionIn("function", c)
	case p.at("constructor"):
		return p.parseFunctionIn("constructor", c)
	case p.at("receive"):
		return p.parseFunctionIn("receive", c)
	case p.at("fallback"):
		if p.peekN(1).text == "(" {
			return p.parseFunctionIn("fallback", c)
		}
		p.advance()
		p.skipDeclaration()
		return nil
	case p.at("modifier"):
		return p.parseFunctionIn("modifier", c)
	case p.at("struct"):
		return p.parseStruct()
	case p.at("enum"):
		return p.parseEnum()
	case p.at("event"):
		return p.parseEvent()
	case p.at("error"):
		if p.peekN(1).kind == tIdent {
			return p.parseErrorDef()
		}
		p.advance()
		p.skipDeclaration()
		return nil
	case p.at("using"):
		p.skipDeclaration()
		return &UsingDef{Pos: p.tok().pos}
	case p.at(";"):
		p.advance()
		return nil
	}
	return p.parseStateVar(c)
}

func (p *parser) parseStruct() Member {
	pos := p.advance().pos // struct
	sd := &StructDef{Pos: pos}
	if p.tok().kind == tIdent {
		sd.Name = p.advance().text
	}
	p.expect("{")
	for p.tok().kind != tEOF && !p.at("}") {
		start := p.i
		ty := p.parseTypeName()
		name := ""
		if p.tok().kind == tIdent {
			name = p.advance().text
		}
		sd.Fields = append(sd.Fields, Param{Name: name, Type: ty, Pos: p.tok().pos})
		p.accept(";")
		if p.i == start {
			p.advance()
		}
	}
	p.accept("}")
	return sd
}

func (p *parser) parseEnum() Member {
	pos := p.advance().pos
	ed := &EnumDef{Pos: pos}
	if p.tok().kind == tIdent {
		ed.Name = p.advance().text
	}
	p.expect("{")
	for p.tok().kind != tEOF && !p.at("}") {
		if p.tok().kind == tIdent {
			ed.Values = append(ed.Values, p.advance().text)
		} else {
			p.advance()
		}
		p.accept(",")
	}
	p.accept("}")
	return ed
}

func (p *parser) parseEvent() Member {
	pos := p.advance().pos
	ed := &EventDef{Pos: pos}
	if p.tok().kind == tIdent {
		ed.Name = p.advance().text
	}
	if p.accept("(") {
		ed.Params = p.parseParamList()
	}
	p.accept("anonymous")
	p.accept(";")
	return ed
}

func (p *parser) parseErrorDef() Member {
	pos := p.advance().pos
	ed := &ErrorDef{Pos: pos}
	if p.tok().kind == tIdent {
		ed.Name = p.advance().text
	}
	if p.accept("(") {
		ed.Params = p.parseParamList()
	}
	p.accept(";")
	return ed
}

var typeKeywords = map[string]bool{
	"address": true, "bool": true, "string": true, "bytes": true, "byte": true,
	"int": true, "uint": true, "fixed": true, "ufixed": true, "var": true,
}

// parseTypeName reads a type, including array suffixes and mapping(...).
func (p *parser) parseTypeName() string {
	var sb strings.Builder
	if p.at("mapping") {
		p.advance()
		sb.WriteString("mapping(")
		if p.accept("(") {
			// mapping(K => V)
			sb.WriteString(p.parseTypeName())
			if p.accept("=>") {
				sb.WriteString("=>")
				sb.WriteString(p.parseTypeName())
				// optional named value
				if p.tok().kind == tIdent && !p.at(")") {
					p.advance()
				}
			}
			p.accept(")")
		}
		sb.WriteString(")")
		return sb.String()
	}
	if p.at("function") {
		// function type; skip its signature
		p.advance()
		if p.accept("(") {
			p.skipParens()
		}
		// visibility / mutability
		for {
			switch p.tok().text {
			case "external", "internal", "pure", "view", "payable":
				p.advance()
				continue
			}
			break
		}
		if p.accept("returns") {
			if p.accept("(") {
				p.skipParens()
			}
		}
		return "function"
	}
	// elementary with size suffix (uint256, bytes32, int8)
	if p.tok().kind == tIdent {
		name := p.advance().text
		// qualified type name Library.Struct
		for p.at(".") && p.peekN(1).kind == tIdent {
			p.advance()
			name += "." + p.advance().text
		}
		sb.WriteString(name)
	} else if p.at("[") {
		// array literal type, rare
		p.skipBrackets()
		sb.WriteString("array")
	} else {
		return ""
	}
	// array suffixes
	for p.at("[") {
		p.advance()
		depth := 1
		var inner strings.Builder
		for p.tok().kind != tEOF && depth > 0 {
			if p.at("[") {
				depth++
			}
			if p.at("]") {
				depth--
				if depth == 0 {
					p.advance()
					break
				}
			}
			inner.WriteString(p.advance().text)
		}
		sb.WriteString("[" + inner.String() + "]")
	}
	return sb.String()
}

func (p *parser) skipBrackets() {
	depth := 0
	for p.tok().kind != tEOF {
		if p.at("[") {
			depth++
		} else if p.at("]") {
			depth--
			p.advance()
			if depth <= 0 {
				return
			}
			continue
		}
		p.advance()
	}
}

func (p *parser) parseParamList() []Param {
	var out []Param
	for p.tok().kind != tEOF && !p.at(")") {
		start := p.i
		pos := p.tok().pos
		ty := p.parseTypeName()
		// storage location
		loc := ""
		switch p.tok().text {
		case "memory", "storage", "calldata":
			loc = p.advance().text
		}
		name := ""
		if p.tok().kind == tIdent {
			name = p.advance().text
		}
		if ty != "" {
			if loc != "" {
				ty += " " + loc
			}
			out = append(out, Param{Name: name, Type: ty, Pos: pos})
		}
		if !p.accept(",") {
			if p.i == start {
				p.advance()
			}
		}
		if p.i == start {
			p.advance()
		}
	}
	p.accept(")")
	return out
}

func (p *parser) parseFunctionIn(kind string, c *Contract) *Func {
	f := p.parseFunction(kind)
	f.Contract = c
	return f
}

func (p *parser) parseFunction(kind string) *Func {
	f := &Func{Kind: kind, Pos: p.tok().pos}
	p.advance() // keyword
	if kind == "function" || kind == "modifier" {
		if p.tok().kind == tIdent && !p.at("(") {
			f.Name = p.advance().text
		}
	}
	if p.accept("(") {
		f.Params = p.parseParamList()
	}
	// header: visibility, mutability, virtual, override, returns, modifiers
	for p.tok().kind != tEOF && !p.at("{") && !p.at(";") {
		switch p.tok().text {
		case "public", "private", "internal", "external":
			f.Vis = p.advance().text
		case "pure", "view", "payable", "constant", "nonpayable":
			f.Mutability = p.advance().text
		case "virtual":
			f.Virtual = true
			p.advance()
		case "override":
			p.advance()
			if p.at("(") {
				p.skipParens()
			}
		case "returns":
			p.advance()
			if p.accept("(") {
				f.Returns = p.parseParamList()
			}
		default:
			// modifier invocation
			if p.tok().kind == tIdent {
				mi := ModifierInvoke{Pos: p.tok().pos}
				mi.Name = p.advance().text
				for p.at(".") && p.peekN(1).kind == tIdent {
					p.advance()
					mi.Name += "." + p.advance().text
				}
				if p.accept("(") {
					mi.Args = p.parseArgList()
				}
				f.Modifiers = append(f.Modifiers, mi)
			} else {
				p.advance()
			}
		}
	}
	if p.accept(";") {
		return f
	}
	if p.at("{") {
		f.Body = p.parseBlock()
	} else {
		p.recover(true)
	}
	return f
}

func (p *parser) parseStateVar(c *Contract) Member {
	pos := p.tok().pos
	ty := p.parseTypeName()
	if ty == "" {
		// couldn't parse; skip a token
		p.diagf(pos, "unrecognized declaration starting with %q", p.tok().text)
		p.advance()
		p.recover(true)
		return nil
	}
	// storage location (rare at contract level)
	switch p.tok().text {
	case "memory", "storage", "calldata":
		p.advance()
	}
	sv := &StateVar{Type: ty, Pos: pos}
	// visibility / constant / immutable may come before or after the name:
	// `uint256 public total;` and `mapping(..) public balances;`
	for {
		switch p.tok().text {
		case "public", "private", "internal", "external":
			sv.Vis = p.advance().text
			continue
		case "constant":
			sv.Constant = true
			p.advance()
			continue
		case "immutable":
			sv.Immutable = true
			p.advance()
			continue
		case "override":
			p.advance()
			if p.at("(") {
				p.skipParens()
			}
			continue
		case "transient":
			p.advance()
			continue
		}
		if p.tok().kind == tIdent && sv.Name == "" {
			sv.Name = p.advance().text
			continue
		}
		break
	}
	if p.accept("=") {
		sv.Init = p.parseExpr()
	}
	p.accept(";")
	return sv
}
