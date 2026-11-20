package sol

var binaryPrec = map[string]int{
	"||": 1,
	"&&": 2,
	"==": 3, "!=": 3,
	"<": 4, ">": 4, "<=": 4, ">=": 4,
	"|":  5,
	"^":  6,
	"&":  7,
	"<<": 8, ">>": 8, ">>>": 8,
	"+": 9, "-": 9,
	"*": 10, "/": 10, "%": 10,
	"**": 11,
}

var assignOps = map[string]bool{
	"=": true, "+=": true, "-=": true, "*=": true, "/=": true, "%=": true,
	"|=": true, "&=": true, "^=": true, "<<=": true, ">>=": true, ">>>=": true,
}

func (p *parser) parseExpr() Expr { return p.parseAssign() }

func (p *parser) parseAssign() Expr {
	lhs := p.parseTernary()
	if assignOps[p.tok().text] {
		op := p.advance().text
		rhs := p.parseAssign()
		return &AssignExpr{Op: op, L: lhs, R: rhs, Posv: lhs.Pos()}
	}
	return lhs
}

func (p *parser) parseTernary() Expr {
	cond := p.parseBinary(1)
	if p.at("?") {
		p.advance()
		then := p.parseAssign()
		p.expect(":")
		els := p.parseAssign()
		return &TernaryExpr{Cond: cond, Then: then, Else: els, Posv: cond.Pos()}
	}
	return cond
}

func (p *parser) parseBinary(minPrec int) Expr {
	lhs := p.parseUnary()
	for {
		op := p.tok().text
		prec, ok := binaryPrec[op]
		if !ok || prec < minPrec {
			break
		}
		p.advance()
		next := prec + 1
		if op == "**" {
			next = prec // right-assoc
		}
		rhs := p.parseBinary(next)
		lhs = &BinaryExpr{Op: op, L: lhs, R: rhs, Posv: lhs.Pos()}
	}
	return lhs
}

func (p *parser) parseUnary() Expr {
	t := p.tok()
	switch t.text {
	case "!", "~", "-", "+", "++", "--":
		p.advance()
		x := p.parseUnary()
		return &UnaryExpr{Op: t.text, X: x, Prefix: true, Posv: t.pos}
	case "delete":
		p.advance()
		x := p.parseUnary()
		return &UnaryExpr{Op: "delete", X: x, Prefix: true, Posv: t.pos}
	}
	x := p.parsePostfix()
	// postfix ++/--
	if p.at("++") || p.at("--") {
		op := p.advance().text
		return &UnaryExpr{Op: op, X: x, Prefix: false, Posv: x.Pos()}
	}
	return x
}

func (p *parser) parsePostfix() Expr {
	x := p.parsePrimary()
	for {
		switch {
		case p.at("."):
			p.advance()
			name := ""
			if p.tok().kind == tIdent {
				name = p.advance().text
			} else if p.at("address") || p.at("value") || p.at("gas") {
				name = p.advance().text
			} else {
				return x
			}
			x = &MemberExpr{X: x, Name: name, Posv: x.Pos()}
		case p.at("["):
			p.advance()
			idx := p.parseExpr()
			p.accept("]")
			x = &IndexExpr{X: x, Index: idx, Posv: x.Pos()}
		case p.at("("):
			p.advance()
			call := &CallExpr{Fn: x, Posv: x.Pos()}
			// named call options: {value: ..., gas: ...}
			if p.at("{") {
				p.advance()
				for p.tok().kind != tEOF && !p.at("}") {
					na := NamedArg{}
					if p.tok().kind == tIdent {
						na.Name = p.advance().text
					}
					if p.accept(":") {
						na.Val = p.parseExpr()
					}
					call.Opts = append(call.Opts, na)
					if !p.accept(",") {
						break
					}
				}
				p.accept("}")
			}
			call.Args = p.parseArgList()
			x = call
		case p.at("{"):
			// call options: to.call{value: 1}("")
			opts := p.parseBraceOpts()
			if p.at("(") {
				p.advance()
				call := &CallExpr{Fn: x, Opts: opts, Posv: x.Pos()}
				call.Args = p.parseArgList()
				x = call
			} else {
				// struct literal used as a bare value
				x = &CallExpr{Fn: x, Opts: append([]NamedArg{{Name: "__struct_literal__"}}, opts...), Posv: x.Pos()}
			}
		default:
			return x
		}
	}
}

func (p *parser) parseBraceOpts() []NamedArg {
	var out []NamedArg
	p.advance() // {
	for p.tok().kind != tEOF && !p.at("}") {
		na := NamedArg{}
		if p.tok().kind == tIdent {
			na.Name = p.advance().text
		}
		if p.accept(":") {
			na.Val = p.parseExpr()
		}
		out = append(out, na)
		if !p.accept(",") {
			break
		}
	}
	p.accept("}")
	return out
}

func (p *parser) parseArgList() []Expr {
	var args []Expr
	for p.tok().kind != tEOF && !p.at(")") {
		if p.at("{") {
			// struct literal argument: Foo({a: 1, b: 2})
			opts := p.parseBraceOpts()
			args = append(args, &CallExpr{Opts: append([]NamedArg{{Name: "__struct_literal__"}}, opts...), Posv: p.tok().pos})
			if !p.accept(",") {
				break
			}
			continue
		}
		start := p.i
		args = append(args, p.parseExpr())
		if p.i == start {
			p.advance()
			continue
		}
		if !p.accept(",") {
			break
		}
	}
	p.accept(")")
	return args
}

func (p *parser) parsePrimary() Expr {
	t := p.tok()
	switch t.kind {
	case tNumber:
		p.advance()
		return &Literal{Kind: "number", Text: t.text, Posv: t.pos}
	case tString, tHexString:
		p.advance()
		// adjacent string concatenation
		text := t.text
		for p.tok().kind == tString || p.tok().kind == tHexString {
			text += p.advance().text
		}
		return &Literal{Kind: "string", Text: text, Posv: t.pos}
	case tIdent:
		switch t.text {
		case "true", "false":
			p.advance()
			return &Literal{Kind: "bool", Text: t.text, Posv: t.pos}
		case "new":
			p.advance()
			ty := p.parseTypeName()
			return &NewExpr{Type: ty, Posv: t.pos}
		case "payable", "address", "bool", "string", "bytes", "byte", "uint", "int":
			p.advance()
			return &TypeExpr{Name: t.text, Posv: t.pos}
		}
		// elementary type with width: uint256, int8, bytes32, ufixed128x18
		if isElementarySized(t.text) {
			p.advance()
			return &TypeExpr{Name: t.text, Posv: t.pos}
		}
		p.advance()
		return &Ident{Name: t.text, Posv: t.pos}
	}
	if t.text == "(" {
		p.advance()
		if p.at(")") {
			p.advance()
			return &TupleExpr{Posv: t.pos}
		}
		var items []Expr
		for p.tok().kind != tEOF && !p.at(")") {
			if p.accept(",") {
				items = append(items, nil)
				continue
			}
			start := p.i
			items = append(items, p.parseExpr())
			if p.i == start {
				p.advance()
				continue
			}
			if !p.accept(",") {
				break
			}
		}
		p.expect(")")
		if len(items) == 1 {
			return items[0]
		}
		return &TupleExpr{Items: items, Posv: t.pos}
	}
	if t.text == "[" {
		p.advance()
		var items []Expr
		for p.tok().kind != tEOF && !p.at("]") {
			items = append(items, p.parseExpr())
			if !p.accept(",") {
				break
			}
		}
		p.accept("]")
		return &ArrayLitExpr{Items: items, Posv: t.pos}
	}
	if t.kind == tEOF {
		return &Ident{Name: "", Posv: t.pos}
	}
	// unknown punctuation: consume to make progress
	p.advance()
	return &Ident{Name: t.text, Posv: t.pos}
}

func isElementarySized(s string) bool {
	// uint8..uint256, int8..int256, bytes1..bytes32, ufixedMxN, fixedMxN
	for _, pre := range []string{"uint", "int"} {
		if len(s) > len(pre) && s[:len(pre)] == pre && allDigits(s[len(pre):]) {
			return true
		}
	}
	for _, pre := range []string{"bytes", "ufixed", "fixed"} {
		if len(s) > len(pre) && s[:len(pre)] == pre {
			return true
		}
	}
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
