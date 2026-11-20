package sol

import (
	"fmt"
	"strings"
)

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tNumber
	tString
	tHexString
	tPunct
)

type token struct {
	kind tokKind
	text string
	pos  Pos
}

type lexer struct {
	src   []rune
	offR  int // rune index
	line  int
	col   int
	pos   Pos // start of current token
	diags *[]Diag
}

func newLexer(src string) *lexer {
	return &lexer{src: []rune(src), line: 1, col: 1, diags: &[]Diag{}}
}

func (l *lexer) byteOff() int {
	// approximate byte offset; good enough for highlighting
	n := 0
	for i := 0; i < l.offR; i++ {
		n += len(string(l.src[i]))
	}
	return n
}

func (l *lexer) peek() rune {
	if l.offR >= len(l.src) {
		return 0
	}
	return l.src[l.offR]
}

func (l *lexer) peekAt(n int) rune {
	if l.offR+n >= len(l.src) {
		return 0
	}
	return l.src[l.offR+n]
}

func (l *lexer) advance() rune {
	r := l.src[l.offR]
	l.offR++
	if r == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return r
}

func (l *lexer) curPos() Pos {
	return Pos{Line: l.line, Col: l.col, Off: l.byteOff()}
}

func (l *lexer) errf(p Pos, f string, a ...any) {
	*l.diags = append(*l.diags, Diag{Line: p.Line, Col: p.Col, Msg: fmt.Sprintf(f, a...)})
}

// stripNatspec skips a NatSpec/comment block, returning its text without markers.
func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }

func (l *lexer) skipTrivia() {
	for l.offR < len(l.src) {
		r := l.peek()
		if isSpace(r) {
			l.advance()
			continue
		}
		if r == '/' && l.peekAt(1) == '/' {
			for l.offR < len(l.src) && l.peek() != '\n' {
				l.advance()
			}
			continue
		}
		if r == '/' && l.peekAt(1) == '*' {
			p := l.curPos()
			l.advance()
			l.advance()
			closed := false
			for l.offR < len(l.src) {
				if l.peek() == '*' && l.peekAt(1) == '/' {
					l.advance()
					l.advance()
					closed = true
					break
				}
				l.advance()
			}
			if !closed {
				l.errf(p, "unterminated block comment")
			}
			continue
		}
		return
	}
}

var multiPuncts = []string{
	">>>=", "<<=", ">>=", "**=", ">>>", "==", "!=", "<=", ">=", "&&", "||",
	"++", "--", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<", ">>",
	"=>", "->", ":=", "**",
}

func (l *lexer) next() token {
	l.skipTrivia()
	l.pos = l.curPos()
	if l.offR >= len(l.src) {
		return token{kind: tEOF, text: "", pos: l.pos}
	}
	r := l.peek()

	// string literals
	if r == '"' || r == '\'' {
		return l.lexString(r)
	}
	// hex"..." hex'...' unicode"..."
	if isIdentStart(r) {
		// Look ahead: hex"..." / unicode"..." attach to the quote.
		save := *l
		start := l.offR
		for l.offR < len(l.src) && isIdentPart(l.peek()) {
			l.advance()
		}
		word := string(l.src[start:l.offR])
		if (word == "hex" || word == "unicode") && (l.peek() == '"' || l.peek() == '\'') {
			q := l.peek()
			base := l.pos
			tk := l.lexString(q)
			tk.text = word + tk.text
			tk.pos = base
			if word == "hex" {
				tk.kind = tHexString
			}
			return tk
		}
		// rewind unless followed by nothing special
		if l.peek() == '"' || l.peek() == '\'' {
			// e.g. `foo"bar"` — treat as ident then string separately
		}
		tk := token{kind: tIdent, text: word, pos: l.pos}
		// restore is unnecessary: we consumed exactly the ident
		_ = save
		return tk
	}
	if r >= '0' && r <= '9' || (r == '.' && l.peekAt(1) >= '0' && l.peekAt(1) <= '9') {
		return l.lexNumber()
	}
	// punctuation
	for _, p := range multiPuncts {
		pr := []rune(p)
		ok := true
		for i := range pr {
			if l.peekAt(i) != pr[i] {
				ok = false
				break
			}
		}
		if ok {
			for range pr {
				l.advance()
			}
			return token{kind: tPunct, text: p, pos: l.pos}
		}
	}
	l.advance()
	return token{kind: tPunct, text: string(r), pos: l.pos}
}

func (l *lexer) lexString(q rune) token {
	p := l.curPos()
	l.advance() // opening quote
	var sb strings.Builder
	sb.WriteRune(q)
	for l.offR < len(l.src) {
		c := l.peek()
		if c == '\\' {
			l.advance()
			if l.offR < len(l.src) {
				e := l.advance()
				switch e {
				case 'n':
					sb.WriteRune('\n')
				case 't':
					sb.WriteRune('\t')
				case 'r':
					sb.WriteRune('\r')
				default:
					sb.WriteRune(e)
				}
			}
			continue
		}
		if c == q {
			l.advance()
			sb.WriteRune(q)
			return token{kind: tString, text: sb.String(), pos: p}
		}
		if c == '\n' {
			l.errf(p, "unterminated string literal")
			break
		}
		sb.WriteRune(l.advance())
	}
	return token{kind: tString, text: sb.String(), pos: p}
}

func (l *lexer) lexNumber() token {
	p := l.curPos()
	start := l.offR
	if l.peek() == '0' && (l.peekAt(1) == 'x' || l.peekAt(1) == 'X') {
		l.advance()
		l.advance()
		for l.offR < len(l.src) && (isHexDigit(l.peek()) || l.peek() == '_') {
			l.advance()
		}
		return token{kind: tNumber, text: string(l.src[start:l.offR]), pos: p}
	}
	for l.offR < len(l.src) {
		c := l.peek()
		if (c >= '0' && c <= '9') || c == '_' || c == '.' || c == 'e' || c == 'E' {
			l.advance()
			continue
		}
		// exponent sign
		if (c == '+' || c == '-') && l.offR > start {
			prev := l.src[l.offR-1]
			if prev == 'e' || prev == 'E' {
				l.advance()
				continue
			}
		}
		break
	}
	return token{kind: tNumber, text: string(l.src[start:l.offR]), pos: p}
}

func isIdentStart(r rune) bool {
	return r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r > 127
}

func isIdentPart(r rune) bool {
	return isIdentStart(r) || (r >= '0' && r <= '9')
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func tokenize(src string) ([]token, []Diag) {
	l := newLexer(src)
	var out []token
	for {
		tk := l.next()
		out = append(out, tk)
		if tk.kind == tEOF {
			break
		}
	}
	return out, *l.diags
}
