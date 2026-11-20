package analyze

import (
	"fmt"
	"regexp"
	"strings"

	"solrecon/internal/sol"
)

// randomnessRule: block attributes used as entropy.
func (a *analyzer) checkRandomness(ctx *fnCtx) {
	if ctx.fn == nil || ctx.fn.Body == nil {
		return
	}
	walkExprs(ctx.fn.Body.Stmts, func(e sol.Expr) {
		a.checkRandomnessExpr(ctx, e, "")
	})
}

var timeUnitSuffix = regexp.MustCompile(`(?i)^(seconds|minutes|hours|days|weeks)$`)

// checkRandomnessExpr looks at binary expressions mixing a block attribute with
// a comparison or modulo.
func (a *analyzer) checkRandomnessExpr(ctx *fnCtx, e sol.Expr, label string) {
	switch x := e.(type) {
	case *sol.BinaryExpr:
		// Only value-deriving uses count as randomness: modulo, bit
		// operations. A plain timestamp comparison is a time window, not
		// entropy, and must not fire.
		switch x.Op {
		case "%", "&", ">>", "<<", "^", "|":
			src, how := entropySource(x)
			if src != "" {
				a.reportWeakRandom(ctx, x.Posv, src, how)
			}
		}
		a.checkRandomnessExpr(ctx, x.L, label)
		a.checkRandomnessExpr(ctx, x.R, label)
	case *sol.AssignExpr:
		a.checkRandomnessExpr(ctx, x.R, label)
	case *sol.CallExpr:
		// keccak256(abi.encodePacked(block.timestamp, ...))
		if isKeccak(x) {
			if src, how := entropySourceInArgs(x); src != "" {
				a.reportWeakRandom(ctx, x.Posv, src, how)
			}
		}
		for _, arg := range x.Args {
			a.checkRandomnessExpr(ctx, arg, label)
		}
	case *sol.TernaryExpr:
		a.checkRandomnessExpr(ctx, x.Cond, label)
		a.checkRandomnessExpr(ctx, x.Then, label)
		a.checkRandomnessExpr(ctx, x.Else, label)
	case *sol.UnaryExpr:
		a.checkRandomnessExpr(ctx, x.X, label)
	case *sol.TupleExpr:
		for _, it := range x.Items {
			a.checkRandomnessExpr(ctx, it, label)
		}
	}
}

// entropySource reports which block attribute is being used as randomness.
// The attribute may sit under casts: uint256(uint160(block.coinbase)).
func entropySource(b *sol.BinaryExpr) (string, string) {
	for _, side := range []sol.Expr{b.L, b.R} {
		if attr := findBlockAttribute(side); attr != "" {
			return attr, describeEntropy(attr)
		}
	}
	return "", ""
}

func findBlockAttribute(e sol.Expr) string {
	attr := ""
	walkExpr(e, func(x sol.Expr) {
		if attr != "" {
			return
		}
		if a := blockAttribute(x); a != "" {
			attr = a
		}
	})
	return attr
}

func isKeccak(c *sol.CallExpr) bool {
	switch fn := c.Fn.(type) {
	case *sol.Ident:
		return fn.Name == "keccak256" || fn.Name == "sha256" || fn.Name == "ripemd160"
	}
	return false
}

func entropySourceInArgs(c *sol.CallExpr) (string, string) {
	for _, arg := range c.Args {
		found := ""
		walkExpr(arg, func(e sol.Expr) {
			if found != "" {
				return
			}
			if attr := blockAttribute(e); attr != "" {
				found = attr
			}
		})
		if found != "" {
			return found, describeEntropy(found)
		}
	}
	return "", ""
}

func blockAttribute(e sol.Expr) string {
	me, ok := e.(*sol.MemberExpr)
	if !ok {
		return ""
	}
	base, ok := me.X.(*sol.Ident)
	if !ok {
		return ""
	}
	if base.Name == "block" {
		switch me.Name {
		case "timestamp", "number", "difficulty", "prevrandao", "coinbase", "gaslimit", "basefee", "blobbasefee":
			return "block." + me.Name
		}
	}
	if base.Name == "now" {
		return "now"
	}
	return ""
}

func describeEntropy(attr string) string {
	switch attr {
	case "block.timestamp", "now":
		return "验证者可以在一定范围内挑选出块时间，同一笔交易打包时间也可被矿工/验证者操纵"
	case "block.number":
		return "出块高度可预测，且出块者可影响交易落在哪个块"
	case "block.difficulty", "block.prevrandao":
		return "难度/prevrandao 可被出块者影响，且在同一块内对所有交易相同"
	case "block.coinbase":
		return "出块者地址由出块者自己决定"
	case "block.gaslimit", "block.basefee", "block.blobbasefee":
		return "这些值由协议与出块者共同决定，对攻击者而言可预测"
	}
	return "该值不是密码学随机源"
}

func (a *analyzer) reportWeakRandom(ctx *fnCtx, pos sol.Pos, src, why string) {
	msg := fmt.Sprintf("以 %s 作为随机性来源。", src)
	exploit := fmt.Sprintf("攻击者无需破解任何密码学原语：%s。更直接的是，攻击者可以在自己的合约里先算出结果，若不中意就 revert 整笔交易，只保留有利的那次；或观察交易进入内存池后，用更高 gas 抢先/夹击以改变实际生效的 %s。若随机数决定抽奖、盲盒、NFT 稀有度或清算顺序，攻击者因此总能拿到有利结果。", why, src)
	fix := "用 Chainlink VRF 等可验证随机函数，或提交-揭示（commit-reveal）两阶段方案；至少不要用单个区块属性，并加入调用者不可控的熵。不要在同一个交易里既产生随机数又立即兑现价值。"
	ctx.emit(findingOpts{
		rule:       "RAND-01",
		category:   CatRandom,
		severity:   SevHigh,
		title:      "使用区块属性作为随机数",
		pos:        pos,
		message:    msg,
		exploit:    exploit,
		fix:        fix,
		confidence: "high",
		tags:       []string{src},
	})
}

// ---- integer rules ----

var verPattern = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// pragmaAllowsWrap reports whether the file's pragma permits <0.8.0, where
// arithmetic wraps silently.
func pragmaAllowsWrap(f *File) bool {
	if f == nil || f.AST.Pragma == "" {
		return false
	}
	s := strings.ToLower(f.AST.Pragma)
	if strings.Contains(s, "experimental") {
		return false
	}
	m := verPattern.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	major := atoiSafe(m[1])
	minor := atoiSafe(m[2])
	if major < 0 {
		return false
	}
	if major == 0 && minor < 8 {
		return true
	}
	// ^0.7.x, >=0.6.0 <0.8.0, 0.7.6 — any bound below 0.8
	if strings.Contains(s, "<0.8") || strings.Contains(s, "<=0.7") {
		return true
	}
	return false
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// checkIntegers flags unsafe arithmetic in pre-0.8 sources and narrowing casts
// everywhere.
// checkIntegerExpr runs the integer rules over a single expression with no
// function body context (used for state variable initializers).
func (a *analyzer) checkIntegerExpr(ctx *fnCtx, e sol.Expr) {
	if e == nil {
		return
	}
	if pragmaAllowsWrap(ctx.file) {
		walkExpr(e, func(x sol.Expr) {
			b, ok := x.(*sol.BinaryExpr)
			if !ok {
				return
			}
			switch b.Op {
			case "+", "-", "*", "**":
			default:
				return
			}
			if isLiteral(b.L) && isLiteral(b.R) {
				return
			}
			ctx.emit(findingOpts{
				rule: "INT-01", category: CatInteger, severity: SevMedium,
				title:      "0.8 之前的算术会静默溢出/下溢",
				pos:        b.Posv,
				message:    "pragma 允许 <0.8.0 编译，状态变量初始化中的算术会按 2^256 取模而不报错。",
				exploit:    "若初始值依赖外部输入或计算结果接近上限，部署时就会写入一个绕回后的错误值，后续所有依赖它的记账都从错误基线开始。",
				fix:        "升级到 Solidity >=0.8.0，或使用 SafeMath。",
				confidence: "medium",
			})
		})
	}
}

func (a *analyzer) checkIntegers(ctx *fnCtx) {
	if ctx.fn == nil || ctx.fn.Body == nil {
		return
	}
	oldPragma := pragmaAllowsWrap(ctx.file)
	if oldPragma {
		a.checkWrapArithmetic(ctx)
	}
	a.checkDowncasts(ctx)
	a.checkUncheckedBlocks(ctx)
	a.checkDivisionPrecision(ctx)
}

// uncheckedRanges returns line ranges covered by `unchecked { ... }`.
func uncheckedRanges(fn *sol.Func) [][2]int {
	var out [][2]int
	walkSimple(fn.Body.Stmts, func(st sol.Stmt) {
		if u, ok := st.(*sol.UncheckedStmt); ok {
			start := u.Posv.Line
			end := start
			if u.Body != nil {
				end = blockEndLine(u.Body)
			}
			out = append(out, [2]int{start, end})
		}
	})
	return out
}

func blockEndLine(b *sol.Block) int {
	if b == nil || len(b.Stmts) == 0 {
		return b.Posv.Line
	}
	last := b.Stmts[len(b.Stmts)-1]
	return stmtEndLine(last)
}

func stmtEndLine(st sol.Stmt) int {
	far := st.Pos().Line
	walkSimple([]sol.Stmt{st}, func(s sol.Stmt) {
		if l := s.Pos().Line; l > far {
			far = l
		}
		switch x := s.(type) {
		case *sol.ExprStmt:
			walkExpr(x.X, func(e sol.Expr) {
				if l := e.Pos().Line; l > far {
					far = l
				}
			})
		}
	})
	// expressions can sit on later lines than their statement start
	walkExprs([]sol.Stmt{st}, func(e sol.Expr) {
		if l := e.Pos().Line; l > far {
			far = l
		}
	})
	return far
}

func lineInRanges(line int, rs [][2]int) bool {
	for _, r := range rs {
		if line >= r[0] && line <= r[1] {
			return true
		}
	}
	return false
}

func (a *analyzer) checkWrapArithmetic(ctx *fnCtx) {
	rs := uncheckedRanges(ctx.fn)
	reported := 0
	walkExprs(ctx.fn.Body.Stmts, func(e sol.Expr) {
		if reported >= 6 {
			return
		}
		b, ok := e.(*sol.BinaryExpr)
		if !ok {
			return
		}
		switch b.Op {
		case "+", "-", "*", "**":
		default:
			return
		}
		if lineInRanges(b.Pos().Line, rs) {
			return
		}
		// skip constant-only arithmetic and loop counters
		if isLiteral(b.L) && isLiteral(b.R) {
			return
		}
		if isPureCounterExpr(b) {
			return
		}
		reported++
		ctx.emit(findingOpts{
			rule:       "INT-01",
			category:   CatInteger,
			severity:   SevMedium,
			title:      "0.8 之前的算术会静默溢出/下溢",
			pos:        b.Posv,
			message:    fmt.Sprintf("pragma 允许 <0.8.0 编译，而这里对非常量做 `%s`，结果会按 2^256 取模，不会报错。", b.Op),
			exploit:    "攻击者构造使结果绕回的值：余额 - 1 在余额为 0 时得到 2^256-1（下溢），或用极大值使乘法溢出成很小的数。这两种都可能被用来凭空增加余额、绕过额度上限或让计数失效。",
			fix:        "升级到 Solidity >=0.8.0（内建检查），或对每个运算使用 SafeMath 的 add/sub/mul；也可用 `unchecked` 之外的显式边界 require 校验。",
			confidence: "medium",
		})
	})
}

func isLiteral(e sol.Expr) bool {
	_, ok := e.(*sol.Literal)
	return ok
}

func isPureCounterExpr(b *sol.BinaryExpr) bool {
	// i++ covered by UnaryExpr; i = i + 1 where i is a loop local
	return false
}

// narrowing casts: uint256 -> uint128/uint8/uint96 etc., int -> uint.
var uintWidth = regexp.MustCompile(`^(u?int)(\d+)$`)

func (a *analyzer) checkDowncasts(ctx *fnCtx) {
	walkExprs(ctx.fn.Body.Stmts, func(e sol.Expr) {
		c, ok := e.(*sol.CallExpr)
		if !ok || len(c.Args) != 1 {
			return
		}
		to := castTypeName(c)
		if to == "" {
			return
		}
		m := uintWidth.FindStringSubmatch(to)
		if m == nil {
			return
		}
		toBits := atoiSafe(m[2])
		if toBits <= 0 || toBits >= 256 {
			return
		}
		from := ctx.exprType(c.Args[0])
		fromBits, _, known := intWidth(ctx, from, c.Args[0])
		if !known || fromBits <= toBits {
			return
		}
		// Skip when caller provably bounds it via require/if in the same
		// function on the same variable.
		if ctx.boundedBefore(c.Args[0], c.Pos()) {
			return
		}
		src := "uint256"
		if from != "" {
			src = typeWord(from)
		}
		ctx.emit(findingOpts{
			rule:       "INT-02",
			category:   CatInteger,
			severity:   SevHigh,
			title:      "收窄类型转换未做上界检查",
			pos:        c.Pos(),
			message:    fmt.Sprintf("把 %s 转成 %s 时没有做上界/符号检查，超出的高位被直接截断。", src, to),
			exploit:    fmt.Sprintf("Solidity 0.8 的溢出检查不覆盖显式类型转换。攻击者传入一个大于 %s 上限（%s）的值，例如用 2^%d，转换后变成 0 或一个很小的数。若该值随后用于记账、额度或价格，攻击者可用它绕过上限或凭空造出额度。", to, maxForWidth(toBits), toBits),
			fix:        fmt.Sprintf("转换前 `require(x <= type(%s).max, \"overflow\");`，或用 SafeCast 的 `toUint%d`，或使用 OpenZeppelin SafeCast 库。", to, toBits),
			confidence: "medium",
			tags:       []string{src + "->" + to},
		})
	})
}

func maxForWidth(bits int) string {
	if bits >= 64 {
		return "极大值"
	}
	return fmt.Sprintf("%d", uint64(1)<<uint(bits)-1)
}

func castTypeName(c *sol.CallExpr) string {
	switch fn := c.Fn.(type) {
	case *sol.TypeExpr:
		return fn.Name
	case *sol.Ident:
		if isElementarySized(fn.Name) || fn.Name == "uint" || fn.Name == "int" {
			return fn.Name
		}
	}
	return ""
}

func isElementarySized(s string) bool {
	return uintWidth.MatchString(s) || strings.HasPrefix(s, "bytes") && len(s) > 5
}

// intWidth determines the bit width of an expression's type, best effort.
// intWidth determines the bit width of an expression's type. known is false
// when the type could not be established, so that casts of unknown values are
// not reported (avoiding false positives on address / struct casts).
func intWidth(ctx *fnCtx, typ string, e sol.Expr) (bits int, signed, known bool) {
	w := typeWord(typ)
	if w == "" {
		if l, ok := e.(*sol.Literal); ok && l.Kind == "number" {
			return 256, false, true
		}
		return 0, false, false
	}
	if w == "address" || w == "payable" {
		return 160, false, true
	}
	if m := uintWidth.FindStringSubmatch(w); m != nil {
		b := atoiSafe(m[2])
		return b, m[1] == "int", true
	}
	if w == "uint" {
		return 256, false, true
	}
	if w == "int" {
		return 256, true, true
	}
	return 0, false, false
}

// boundedBefore finds a require/if comparing the same identifier before pos.
func (ctx *fnCtx) boundedBefore(arg sol.Expr, pos sol.Pos) bool {
	id, ok := arg.(*sol.Ident)
	if !ok {
		return false
	}
	name := id.Name
	bounded := false
	walkSimple(ctx.fn.Body.Stmts, func(st sol.Stmt) {
		if bounded || st.Pos().Line >= pos.Line {
			return
		}
		switch s := st.(type) {
		case *sol.ExprStmt:
			c, ok := s.X.(*sol.CallExpr)
			if !ok {
				return
			}
			if fnID, ok := c.Fn.(*sol.Ident); !ok || (fnID.Name != "require" && fnID.Name != "assert") {
				return
			}
			if len(c.Args) == 0 {
				return
			}
			cond := c.Args[0]
			if exprMentions(cond, name) && hasUpperBound(cond, name) {
				bounded = true
			}
		case *sol.IfStmt:
			// if (x > MAX) revert;  — a bound check
			if exprMentions(s.Cond, name) && hasUpperBound(s.Cond, name) && branchAborts(s) {
				bounded = true
			}
		}
	})
	return bounded
}

func hasUpperBound(e sol.Expr, name string) bool {
	hit := false
	walkExpr(e, func(x sol.Expr) {
		b, ok := x.(*sol.BinaryExpr)
		if !ok {
			return
		}
		switch b.Op {
		case "<", "<=", ">", ">=":
		default:
			return
		}
		// `name < CONST` or `CONST > name` both bound the value from above
		if exprMentions(b.L, name) && !exprMentions(b.R, name) && isBoundValue(b.R) {
			hit = true
		}
		if exprMentions(b.R, name) && !exprMentions(b.L, name) && isBoundValue(b.L) {
			hit = true
		}
	})
	return hit
}

// branchAborts reports whether an if-branch rejects execution.
func branchAborts(s *sol.IfStmt) bool {
	aborts := false
	walkSimple([]sol.Stmt{s.Then}, func(st sol.Stmt) {
		switch x := st.(type) {
		case *sol.RevertStmt:
			aborts = true
		case *sol.ExprStmt:
			if c, ok := x.X.(*sol.CallExpr); ok {
				if id, ok := c.Fn.(*sol.Ident); ok && id.Name == "require" {
					aborts = true
				}
			}
		case *sol.ReturnStmt:
			aborts = true
		}
	})
	return aborts
}

func isBoundValue(e sol.Expr) bool {
	if isLiteral(e) {
		return true
	}
	me, ok := e.(*sol.MemberExpr)
	if ok {
		// type(uint128).max
		if me.Name == "max" {
			if _, ok := me.X.(*sol.CallExpr); ok {
				return true
			}
		}
	}
	return false
}

func (a *analyzer) checkUncheckedBlocks(ctx *fnCtx) {
	for _, r := range uncheckedRanges(ctx.fn) {
		// find the containing node to anchor
		ctx.emit(findingOpts{
			rule:       "INT-03",
			category:   CatInteger,
			severity:   SevInfo,
			title:      "unchecked 区块关闭了溢出检查",
			pos:        sol.Pos{Line: r[0], Col: 1},
			endLine:    r[1],
			message:    "该区块内的算术不会自动检查溢出/下溢，只有确认取值范围安全时才应使用。",
			exploit:    "若区块内的减法或乘法能收到外部控制的值，攻击者可用下溢得到极大数或让计算结果绕回，从而绕过余额/额度判断。",
			fix:        "复核该区块内每个运算符的输入是否都有显式边界保证；否则移出 unchecked。",
			confidence: "low",
		})
	}
}

func (a *analyzer) checkDivisionPrecision(ctx *fnCtx) {
	// a / b then * c in the same expression tree loses precision
	walkExprs(ctx.fn.Body.Stmts, func(e sol.Expr) {
		b, ok := e.(*sol.BinaryExpr)
		if !ok || b.Op != "*" {
			return
		}
		if leftDiv(b.L) || rightDiv(b.R) {
			ctx.emit(findingOpts{
				rule:       "INT-04",
				category:   CatInteger,
				severity:   SevLow,
				title:      "先除后乘导致精度丢失",
				pos:        b.Posv,
				message:    "乘法链条里包含除法，整数除法会向下取整，先除后乘的结果会系统性偏小。",
				exploit:    "攻击者把金额拆成许多笔小额操作，让每一笔的除法取整损失累积，或反向利用取整差额套利（常见于份额/费率计算）。金额越大，被吞掉的余数越多。",
				fix:        "改为先乘后除，或用更高精度（如 1e27 定点数、mulDiv），并明确指定舍入方向。",
				confidence: "low",
			})
		}
	})
}

func leftDiv(e sol.Expr) bool {
	switch x := e.(type) {
	case *sol.BinaryExpr:
		if x.Op == "/" {
			return true
		}
		return leftDiv(x.L) || leftDiv(x.R)
	case *sol.CallExpr:
		return false
	}
	return false
}

func rightDiv(e sol.Expr) bool { return leftDiv(e) }
