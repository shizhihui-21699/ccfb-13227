package sol

import "strings"

func (p *parser) parseBlock() *Block {
	b := &Block{Posv: p.tok().pos}
	if !p.expect("{") {
		p.recover(false)
		return b
	}
	for p.tok().kind != tEOF && !p.at("}") {
		start := p.i
		s := p.parseStmt()
		if s != nil {
			b.Stmts = append(b.Stmts, s)
		}
		if p.i == start {
			p.advance()
		}
	}
	p.accept("}")
	return b
}

func (p *parser) parseStmt() Stmt {
	pos := p.tok().pos
	switch {
	case p.at("{"):
		return p.parseBlock()
	case p.at("if"):
		p.advance()
		p.expect("(")
		cond := p.parseExpr()
		p.expect(")")
		st := &IfStmt{Cond: cond, Posv: pos}
		st.Then = p.parseStmt()
		if p.accept("else") {
			st.Else = p.parseStmt()
		}
		return st
	case p.at("for"):
		p.advance()
		p.expect("(")
		fs := &ForStmt{Posv: pos}
		if !p.at(";") {
			fs.Init = p.parseSimpleStmt()
		}
		p.accept(";")
		if !p.at(";") {
			fs.Cond = p.parseExpr()
		}
		p.accept(";")
		if !p.at(")") {
			fs.Post = p.parseSimpleStmt()
		}
		p.expect(")")
		fs.Body = p.parseStmt()
		return fs
	case p.at("while"):
		p.advance()
		p.expect("(")
		cond := p.parseExpr()
		p.expect(")")
		return &WhileStmt{Cond: cond, Body: p.parseStmt(), Posv: pos}
	case p.at("do"):
		p.advance()
		body := p.parseStmt()
		p.expect("while")
		p.expect("(")
		cond := p.parseExpr()
		p.expect(")")
		p.accept(";")
		return &DoWhileStmt{Body: body, Cond: cond, Posv: pos}
	case p.at("return"):
		p.advance()
		rs := &ReturnStmt{Posv: pos}
		if !p.at(";") && !p.at("}") {
			rs.Value = p.parseExpr()
		}
		p.accept(";")
		return rs
	case p.at("emit"):
		p.advance()
		rs := &EmitStmt{Posv: pos}
		if e, ok := p.parseExpr().(*CallExpr); ok {
			rs.Call = e
		}
		p.accept(";")
		return rs
	case p.at("revert"):
		p.advance()
		rs := &RevertStmt{Posv: pos}
		if p.tok().kind == tIdent && p.peekN(1).text == "(" {
			if e, ok := p.parseExpr().(*CallExpr); ok {
				rs.Call = e
			}
		}
		p.accept(";")
		return rs
	case p.at("unchecked"):
		p.advance()
		us := &UncheckedStmt{Posv: pos}
		us.Body = p.parseBlock()
		return us
	case p.at("assembly"):
		p.advance()
		// optional dialect string
		if p.tok().kind == tString {
			p.advance()
		}
		if p.accept("(") {
			p.skipParens()
		}
		var sb strings.Builder
		depth := 0
		for p.tok().kind != tEOF {
			if p.at("{") {
				depth++
			} else if p.at("}") {
				depth--
			}
			if depth == 0 && p.tok().kind != tEOF && sb.Len() > 0 {
				p.advance()
				break
			}
			if p.tok().kind != tEOF {
				sb.WriteString(p.advance().text)
				sb.WriteString(" ")
			}
			if depth == 0 && !p.at("{") && sb.Len() > 1 {
				break
			}
		}
		return &AssemblyStmt{Raw: strings.TrimSpace(sb.String()), Posv: pos}
	case p.at("try"):
		p.advance()
		ts := &TryStmt{Posv: pos}
		if e, ok := p.parseExpr().(*CallExpr); ok {
			ts.Call = e
		}
		if p.accept("returns") {
			if p.at("(") {
				p.skipParens()
			}
		}
		ts.Body = p.parseBlock()
		for p.at("catch") {
			p.advance()
			for p.tok().kind != tEOF && !p.at("{") {
				p.advance()
			}
			ts.Catch = append(ts.Catch, p.parseBlock())
		}
		return ts
	case p.at("break"):
		p.advance()
		p.accept(";")
		return &BreakStmt{Posv: pos}
	case p.at("continue"):
		p.advance()
		p.accept(";")
		return &ContinueStmt{Posv: pos}
	case p.at("delete"):
		p.advance()
		ds := &DeleteStmt{Posv: pos}
		ds.X = p.parseExpr()
		p.accept(";")
		return ds
	case p.at(";"):
		p.advance()
		return nil
	case p.at("_") && p.peekN(1).text == ";":
		p.advance()
		p.accept(";")
		return nil
	}
	return p.parseSimpleStmt()
}

// parseSimpleStmt parses an expression statement, possibly a declaration.
func (p *parser) parseSimpleStmt() Stmt {
	pos := p.tok().pos
	// var (x, y) = ...
	if p.at("var") && p.peekN(1).text == "(" {
		return p.parseTupleDecl(pos, "var")
	}
	// tuple declaration: (T a, T b) = ... OR (a, b) = ...
	if p.at("(") {
		save := p.i
		types, names, ok := p.tryParseTupleDeclHeader()
		if ok && p.at("=") {
			p.advance()
			init := p.parseExpr()
			p.accept(";")
			return &TupleDecl{Types: types, Names: names, Init: init, Posv: pos}
		}
		p.i = save
	}
	// leading type declaration: uint x; MyStruct s = ...; (Type followed by ident)
	if p.looksLikeDecl() {
		ty := p.parseTypeName()
		loc := ""
		switch p.tok().text {
		case "memory", "storage", "calldata":
			loc = p.advance().text
		}
		name := ""
		if p.tok().kind == tIdent {
			name = p.advance().text
		}
		if loc != "" {
			ty += " " + loc
		}
		if name != "" {
			d := &VarDecl{Type: ty, Name: name, Posv: pos}
			if p.accept("=") {
				d.Init = p.parseExpr()
			}
			p.accept(";")
			return d
		}
	}
	x := p.parseExpr()
	es := &ExprStmt{X: x, Posv: pos}
	p.accept(";")
	return es
}

func (p *parser) parseTupleDecl(pos Pos, _ string) Stmt {
	p.advance() // var
	p.expect("(")
	var names []string
	for p.tok().kind != tEOF && !p.at(")") {
		if p.tok().kind == tIdent {
			names = append(names, p.advance().text)
		} else {
			p.advance()
		}
		p.accept(",")
	}
	p.expect(")")
	p.accept("=")
	init := p.parseExpr()
	p.accept(";")
	return &TupleDecl{Names: names, Init: init, Posv: pos}
}

// tryParseTupleDeclHeader attempts `(T a, T b)` or `(a, b)` without consuming on failure.
func (p *parser) tryParseTupleDeclHeader() (types, names []string, ok bool) {
	start := p.i
	defer func() {
		if !ok {
			p.i = start
		}
	}()
	if !p.accept("(") {
		return nil, nil, false
	}
	for p.tok().kind != tEOF && !p.at(")") {
		// empty slot
		if p.accept(",") {
			types = append(types, "")
			names = append(names, "")
			continue
		}
		if p.tok().kind != tIdent {
			return nil, nil, false
		}
		first := p.advance().text
		if p.peekN(0).kind == tIdent || p.at("memory") || p.at("storage") || p.at("calldata") {
			// type then name
			ty := first
			switch p.tok().text {
			case "memory", "storage", "calldata":
				ty += " " + p.advance().text
			}
			name := ""
			if p.tok().kind == tIdent {
				name = p.advance().text
			}
			types = append(types, ty)
			names = append(names, name)
		} else {
			// bare name
			types = append(types, "")
			names = append(names, first)
		}
		if !p.accept(",") {
			break
		}
	}
	if !p.accept(")") {
		return nil, nil, false
	}
	return types, names, true
}

var declAmbiguous = map[string]bool{
	"address": true, "bool": true, "string": true, "bytes": true, "byte": true,
	"int": true, "uint": true, "mapping": true, "var": true, "payable": true,
}

// looksLikeDecl decides whether the current position starts a local declaration.
func (p *parser) looksLikeDecl() bool {
	t := p.tok()
	if t.kind != tIdent {
		return false
	}
	switch t.text {
	case "memory", "storage", "calldata", "returns", "delete", "new", "true", "false", "this", "super", "emit", "revert", "break", "continue", "return", "if", "for", "while", "do", "try", "catch", "unchecked", "assembly", "function", "mapping", "type":
		return false
	}
	n1 := p.peekN(1)
	if n1.kind == tIdent {
		// `Foo bar` or `uint x`
		switch n1.text {
		case "public", "private", "internal", "external", "constant", "immutable":
			return false
		}
		return true
	}
	// `Foo[] memory x`, `uint256[2] x`
	if n1.text == "[" {
		// scan for closing bracket then ident
		j := p.i + 1
		depth := 0
		for j < len(p.toks) && j < p.i+40 {
			if p.toks[j].text == "[" {
				depth++
			} else if p.toks[j].text == "]" {
				depth--
				if depth == 0 {
					nj := p.toks[j+1]
					if nj.kind == tIdent && nj.text != "memory" && nj.text != "storage" && nj.text != "calldata" {
						return true
					}
					if nj.text == "memory" || nj.text == "storage" || nj.text == "calldata" {
						return true
					}
					return false
				}
			}
			j++
		}
		return false
	}
	// `uint256 memory`? no. `Foo memory x`
	if n1.text == "memory" || n1.text == "storage" || n1.text == "calldata" {
		return true
	}
	return false
}
