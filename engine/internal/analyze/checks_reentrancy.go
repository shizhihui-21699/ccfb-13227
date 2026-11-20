package analyze

import (
	"fmt"
	"strings"

	"solrecon/internal/sol"
)

// reentrancyRule: external call happens, then contract state is written.
func (a *analyzer) checkReentrancy(ctx *fnCtx) {
	if ctx.fn == nil || ctx.fn.Body == nil {
		return
	}
	if ctx.guard {
		return
	}
	// State writes that are themselves part of a lock (status = _ENTERED) are
	// guard bookkeeping, not business state.
	lockVars := map[string]bool{}
	for name := range ctx.state {
		if looksLikeLockVar(name) {
			lockVars[name] = true
		}
	}

	type callRec struct {
		pos     sol.Pos
		kind    callKind
		desc    string
		fnText  string
		checked bool // every path after it passes through require(ok)
	}

	var active []callRec
	readBefore := map[string]bool{}

	// Pre-compute lines of success checks that abort on failure, so a write
	// after such a check is attributed to a guarded call.
	ctx.walkOrdered(ctx.fn.Body.Stmts, func(ev flowEvent) {
		switch ev.kind {
		case evRead:
			if sv, ok := ctx.stateVarOf(ev.target); ok {
				if !lockVars[sv.Name] {
					readBefore[sv.Name] = true
				}
			}
		case evCall:
			if ev.ck == callValueTransfer {
				return // 2300-gas stipend cannot re-enter meaningfully
			}
			active = append(active, callRec{pos: ev.pos, kind: ev.ck, desc: ev.desc, fnText: callText(ev.call)})
		case evCheck:
			// require(ok) passes: everything already executed stays checked
			for i := range active {
				active[i].checked = true
			}
		case evWrite:
			if len(active) == 0 {
				return
			}
			sv, ok := ctx.stateVarOf(ev.target)
			if !ok || lockVars[sv.Name] {
				return
			}
			if sv.Immutable || sv.Constant {
				return
			}
			// Report the first call that precedes this write.
			first := active[0]
			sev := SevHigh
			conf := "high"
			why := ""
			switch first.kind {
			case callDelegate:
				sev, conf = SevHigh, "high"
				why = "delegatecall 会在调用方存储上下文中执行被调用地址的代码"
			case callLowLevel:
				sev, conf = SevHigh, "high"
				why = "低级调用把执行权交给任意地址"
			case callHighLevel:
				sev, conf = SevHigh, "high"
				why = "被调用的外部合约代码可被攻击者控制（或本身就是可重入的代币）"
			case callSelf:
				sev, conf = SevMedium, "medium"
				why = "this.f() 走外部调用路径，会重新进入合约"
			default:
				sev, conf = SevMedium, "low"
				why = "调用可能回到本合约"
			}
			if first.checked {
				sev = SevMedium
				if conf == "high" {
					conf = "medium"
				}
			}
			// Writes that merely cache a value read before the call are less
			// dangerous; writing something the call's outcome depends on is not.
			amountVar := readBefore[sv.Name]
			tags := []string{}
			if amountVar {
				tags = append(tags, "state-used-before-call")
				conf = "high"
			}
			msg := fmt.Sprintf("函数 %s 先对外部地址执行了 %s，之后才写入状态 %s。外部调用会把控制权交给对方，对方可以在返回值之前回调本合约，此时 %s 仍是旧值。",
				fnLabel(ctx.fn), first.fnText, ev.writeDesc, ev.writeDesc)
			exploit := fmt.Sprintf(
				"攻击合约在接到 %s 的回调时（例如代币的 transfer 钩子、ETH 接收的 receive()），再次调用本合约中同样会执行到该调用点的函数。由于 %s 在调用返回后才更新，重入的那一次读到旧值，可以重复取款/重复计数/重复领取，直到合约余额或额度被耗尽。",
				shortCall(first.desc), ev.writeDesc)
			if amountVar {
				exploit += fmt.Sprintf(" 注意 %s 在调用前已被读取并参与计算，重入路径上该读取同样拿到旧值，放大影响。", sv.Name)
			}
			fix := fmt.Sprintf("按 checks-effects-interactions 顺序重排：在 %s 之前完成 %s 的写入；或加上 nonReentrant 互斥锁；或在调用后核对不变量（如余额差）。", first.fnText, ev.writeDesc)
			ctx.emit(findingOpts{
				rule:        "REENT-01",
				category:    CatReentrancy,
				severity:    sev,
				title:       "外部调用后更新状态（重入）",
				pos:         first.pos,
				endLine:     ev.pos.Line,
				message:     msg + "（" + why + "）",
				exploit:     exploit,
				fix:         fix,
				confidence:  conf,
				relatedLine: ev.pos.Line,
				relatedTag:  "状态写入位置：" + ev.writeDesc,
				tags:        tags,
			})
			// One finding per call site; keep scanning for other call sites.
			active = nil
		}
	})
}

func fnLabel(fn *sol.Func) string {
	if fn.Name != "" {
		return fn.Name
	}
	return fn.Kind
}

func shortCall(desc string) string {
	if desc == "" {
		return "外部调用"
	}
	return desc
}

func callText(c *sol.CallExpr) string {
	if c == nil {
		return "外部调用"
	}
	switch fn := c.Fn.(type) {
	case *sol.MemberExpr:
		recv := exprText(fn.X)
		return recv + "." + fn.Name + "(…)"
	case *sol.Ident:
		return fn.Name + "(…)"
	}
	return "调用"
}

func exprText(e sol.Expr) string {
	switch x := e.(type) {
	case *sol.Ident:
		return x.Name
	case *sol.MemberExpr:
		return exprText(x.X) + "." + x.Name
	case *sol.IndexExpr:
		return exprText(x.X) + "[…]"
	case *sol.CallExpr:
		return exprText(x.Fn) + "(…)"
	case *sol.TypeExpr:
		return x.Name
	case *sol.Literal:
		return x.Text
	}
	return "…"
}

// uncheckedRule: return values of low-level calls and bool-returning token
// methods are dropped.
func (a *analyzer) checkUncheckedCalls(ctx *fnCtx) {
	if ctx.fn == nil || ctx.fn.Body == nil {
		return
	}
	// Track statements whose result is discarded.
	var visit func(list []sol.Stmt)
	visit = func(list []sol.Stmt) {
		for _, st := range list {
			switch s := st.(type) {
			case *sol.Block:
				visit(s.Stmts)
			case *sol.IfStmt:
				visitStmtChildren(s.Then, visit)
				visitStmtChildren(s.Else, visit)
				// calls in the condition are checked
			case *sol.ForStmt:
				visitStmtChildren(s.Init, visit)
				visitStmtChildren(s.Body, visit)
				visitStmtChildren(s.Post, visit)
			case *sol.WhileStmt:
				visitStmtChildren(s.Body, visit)
			case *sol.DoWhileStmt:
				visitStmtChildren(s.Body, visit)
			case *sol.UncheckedStmt:
				visit(s.Body.Stmts)
			case *sol.TryStmt:
				visit(s.Body.Stmts)
				for _, c := range s.Catch {
					visit(c.Stmts)
				}
			case *sol.ExprStmt:
				// a bare call statement: its result is discarded
				if c, ok := s.X.(*sol.CallExpr); ok {
					ctx.reportUnchecked(c, "结果被直接丢弃", s.Posv)
				}
				// assignment whose value is never used later is handled below
			}
		}
	}
	visit(ctx.fn.Body.Stmts)
	// Second pass: tuple assignments whose bool slot is never inspected.
	var tuples func(list []sol.Stmt)
	tuples = func(list []sol.Stmt) {
		for _, st := range list {
			switch s := st.(type) {
			case *sol.Block:
				tuples(s.Stmts)
			case *sol.IfStmt:
				visitTupleBranch(s.Then, tuples)
				visitTupleBranch(s.Else, tuples)
			case *sol.ForStmt:
				visitTupleBranch(s.Init, tuples)
				visitTupleBranch(s.Body, tuples)
				visitTupleBranch(s.Post, tuples)
			case *sol.WhileStmt:
				visitTupleBranch(s.Body, tuples)
			case *sol.DoWhileStmt:
				visitTupleBranch(s.Body, tuples)
			case *sol.UncheckedStmt:
				tuples(s.Body.Stmts)
			case *sol.TryStmt:
				tuples(s.Body.Stmts)
				for _, c := range s.Catch {
					tuples(c.Stmts)
				}
			case *sol.TupleDecl:
				ctx.checkIgnoredTupleBool(s)
			}
		}
	}
	tuples(ctx.fn.Body.Stmts)
}

func visitTupleBranch(st sol.Stmt, visit func([]sol.Stmt)) {
	switch s := st.(type) {
	case *sol.Block:
		visit(s.Stmts)
	case nil:
	default:
		visit([]sol.Stmt{st})
	}
}

func visitStmtChildren(st sol.Stmt, visit func([]sol.Stmt)) {
	switch s := st.(type) {
	case *sol.Block:
		visit(s.Stmts)
	case nil:
	default:
		visit([]sol.Stmt{st})
	}
}

// reportUnchecked flags a call whose success value is not inspected.
func (ctx *fnCtx) reportUnchecked(c *sol.CallExpr, how string, pos sol.Pos) {
	kind, desc := ctx.classifyCall(c)
	if kind == callNone || kind == callInternal || kind == callSelf || kind == callValueTransfer {
		return
	}
	// staticcall in a view/read path still returns success; flag too.
	if kind == callHighLevel && !returnsBool(ctx, c) {
		return
	}
	title := "外部调用返回值未检查"
	sev := SevHigh
	exploit := "低级调用失败时不会 revert，而是返回 false。忽略返回值意味着失败被当作成功继续执行：攻击者可以用一个必然失败的调用（例如 gas 耗尽的收款合约、黑名单代币）让合约在“转账未成功”的状态下继续记账，从而白拿资产或重复放行。"
	fix := "用 `(bool ok, ) = target.call{...}(); require(ok, \"call failed\");`，或使用 try/catch；对 ERC20 的 transfer/transferFrom 用 SafeERC20，或 `require(token.transfer(...))`。"
	conf := "high"
	switch kind {
	case callDelegate:
		title = "delegatecall 返回值未检查"
		exploit = "delegatecall 失败只返回 false。不检查就继续执行，会把“升级/执行失败”当成成功，后续逻辑基于未初始化的返回值运行，可被用来绕过执行结果校验。"
	case callHighLevel:
		title = "代币转账返回值未检查"
		sev = SevHigh
		exploit = "ERC20 的 transfer/transferFrom 在失败时返回 false 而不是 revert（USDT 等甚至不返回数据）。忽略返回值时，合约会认为转账已经完成并继续记账：用户可以领到资产而代币根本没转出，或凭空增加余额。"
		conf = "medium"
	}
	ctx.emit(findingOpts{
		rule:       "UNCHK-01",
		category:   CatUnchecked,
		severity:   sev,
		title:      title,
		pos:        posOfCallOr(c, pos),
		message:    fmt.Sprintf("对 %s 的调用（%s）没有检查返回值。", shortCall(desc), how),
		exploit:    exploit,
		fix:        fix,
		confidence: conf,
	})
}

func posOfCallOr(c *sol.CallExpr, fallback sol.Pos) sol.Pos {
	if c != nil && !c.Pos().IsZero() {
		return c.Pos()
	}
	return fallback
}

// returnsBool decides whether a member call names a known bool-returning token
// method, or the receiver type declares a bool return for it.
func returnsBool(ctx *fnCtx, c *sol.CallExpr) bool {
	me, ok := c.Fn.(*sol.MemberExpr)
	if !ok {
		return false
	}
	switch me.Name {
	case "transfer", "transferFrom", "approve", "send", "mint", "burn", "burnFrom":
		// ERC20/721 style; check the interface declaration when available
		if ctx.receiverDeclaresBool(me) {
			return true
		}
		switch me.Name {
		case "transfer", "transferFrom", "approve", "send", "mint", "burn", "burnFrom":
			return true
		}
	}
	return false
}

// receiverDeclaresBool looks up the receiver's declared type and its method.
func (ctx *fnCtx) receiverDeclaresBool(me *sol.MemberExpr) bool {
	typ := typeWord(ctx.exprType(me.X))
	if typ == "" {
		return false
	}
	c := ctx.a.prog.Contracts[typ]
	if c == nil {
		return false
	}
	for _, m := range c.Members {
		if fn, ok := m.(*sol.Func); ok && fn.Name == me.Name {
			for _, r := range fn.Returns {
				if typeWord(r.Type) == "bool" {
					return true
				}
			}
		}
	}
	return false
}

// checkIgnoredTupleBool catches `(bool ok, ) = ...` where `ok` is never read.
func (ctx *fnCtx) checkIgnoredTupleBool(td *sol.TupleDecl) {
	if ctx.fn == nil || td.Init == nil {
		return
	}
	c, ok := td.Init.(*sol.CallExpr)
	if !ok {
		return
	}
	kind, desc := ctx.classifyCall(c)
	if kind == callNone || kind == callInternal || kind == callValueTransfer {
		return
	}
	// find declared name of first slot
	idx := -1
	for i, n := range td.Names {
		if n != "" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	name := td.Names[idx]
	typ := ""
	if idx < len(td.Types) {
		typ = td.Types[idx]
	}
	if typeWord(typ) != "bool" {
		return
	}
	if ctx.nameUsedAfter(ctx.fn.Body.Stmts, name, td.Posv) {
		return
	}
	ctx.emit(findingOpts{
		rule:       "UNCHK-02",
		category:   CatUnchecked,
		severity:   SevMedium,
		title:      "调用结果赋给变量但从未检查",
		pos:        td.Posv,
		message:    fmt.Sprintf("对 %s 的调用结果存入 `%s`，但之后从未读取该变量。", shortCall(desc), name),
		exploit:    "调用失败会以 false 返回。变量被声明却从未进入 require/if，等同于丢弃返回值：攻击者让调用失败即可让合约在半完成状态下继续执行。",
		fix:        fmt.Sprintf("在调用后立即 `require(%s, \"failed\");`，或改用 SafeERC20。", name),
		confidence: "medium",
	})
}

func (ctx *fnCtx) nameUsedAfter(stmts []sol.Stmt, name string, after sol.Pos) bool {
	found := false
	walkExprs(stmts, func(e sol.Expr) {
		if found || e.Pos().Line < after.Line {
			return
		}
		switch x := e.(type) {
		case *sol.Ident:
			if x.Name == name && x.Pos().Line > after.Line {
				found = true
			}
		}
	})
	return found
}

// drop unused import guard
var _ = strings.TrimSpace
