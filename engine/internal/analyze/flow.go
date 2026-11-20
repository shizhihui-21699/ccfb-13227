package analyze

import (
	"strings"

	"solrecon/internal/sol"
)

// ---- source order traversal ----

type evKind int

const (
	evCall evKind = iota
	evWrite
	evRead
	evCheck
)

type flowEvent struct {
	kind evKind
	pos  sol.Pos
	// for evCall
	call *sol.CallExpr
	ck   callKind
	desc string
	// for evWrite
	writeDesc string
	target    sol.Expr
}

// walkOrdered visits statements in source order, invoking cb for each external
// call and each state mutation. It is path-aware for if/else and loops: the
// set of calls that "may have executed" is unioned at join points.
func (ctx *fnCtx) walkOrdered(stmts []sol.Stmt, cb func(flowEvent)) {
	s := &flowScan{ctx: ctx, cb: cb}
	s.stmts(stmts)
}

type flowScan struct {
	ctx   *fnCtx
	calls []pendingCall // calls that may have run on some path up to here
	cb    func(flowEvent)
}

func clonePending(p []pendingCall) []pendingCall {
	out := make([]pendingCall, len(p))
	copy(out, p)
	return out
}

func mergePending(a, b []pendingCall) []pendingCall {
	out := clonePending(a)
	for _, x := range b {
		dup := false
		for _, y := range out {
			if y.pos == x.pos && y.kind == x.kind {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, x)
		}
	}
	return out
}

func (s *flowScan) stmts(list []sol.Stmt) {
	for _, st := range list {
		s.stmt(st)
	}
}

func (s *flowScan) stmt(x sol.Stmt) {
	switch st := x.(type) {
	case nil:
		return
	case *sol.Block:
		s.stmts(st.Stmts)
	case *sol.IfStmt:
		s.expr(st.Cond)
		base := clonePending(s.calls)
		s.calls = clonePending(base)
		s.stmt(st.Then)
		thenOut := s.calls
		s.calls = clonePending(base)
		if st.Else != nil {
			s.stmt(st.Else)
		}
		s.calls = mergePending(thenOut, s.calls)
	case *sol.ForStmt:
		s.stmt(st.Init)
		if st.Cond != nil {
			s.expr(st.Cond)
		}
		base := clonePending(s.calls)
		s.calls = clonePending(base)
		s.stmt(st.Body)
		if st.Post != nil {
			s.stmt(st.Post)
		}
		s.calls = mergePending(base, s.calls)
	case *sol.WhileStmt:
		s.expr(st.Cond)
		base := clonePending(s.calls)
		s.calls = clonePending(base)
		s.stmt(st.Body)
		s.calls = mergePending(base, s.calls)
	case *sol.DoWhileStmt:
		base := clonePending(s.calls)
		s.calls = clonePending(base)
		s.stmt(st.Body)
		s.expr(st.Cond)
		s.calls = mergePending(base, s.calls)
	case *sol.UncheckedStmt:
		s.stmt(st.Body)
	case *sol.ReturnStmt:
		if st.Value != nil {
			s.expr(st.Value)
		}
		s.calls = nil // returns end the path
	case *sol.EmitStmt:
		// an event is not an external call
		if st.Call != nil {
			for _, a := range st.Call.Args {
				s.expr(a)
			}
		}
	case *sol.RevertStmt:
		// `revert CustomError(...)` is not an external call; only its
		// arguments can contain real calls.
		if st.Call != nil {
			for _, a := range st.Call.Args {
				s.expr(a)
			}
			for _, o := range st.Call.Opts {
				s.expr(o.Val)
			}
		}
	case *sol.ExprStmt:
		s.expr(st.X)
		if s.ctx.isSuccessCheck(st.X) {
			s.cb(flowEvent{kind: evCheck, pos: st.Pos()})
		}
	case *sol.DeleteStmt:
		s.expr(st.X)
		s.write(st.X, "delete")
	case *sol.VarDecl:
		if st.Init != nil {
			s.expr(st.Init)
		}
	case *sol.TupleDecl:
		if st.Init != nil {
			s.expr(st.Init)
		}
	case *sol.TryStmt:
		if st.Call != nil {
			s.expr(st.Call)
		}
		// try param lists are skipped by the parser; body and catch blocks
		// execute on mutually exclusive paths.
		base := clonePending(s.calls)
		s.calls = clonePending(base)
		s.stmt(st.Body)
		bodyOut := s.calls
		s.calls = clonePending(base)
		for _, c := range st.Catch {
			s.stmt(c)
		}
		s.calls = mergePending(bodyOut, s.calls)
	case *sol.AssemblyStmt:
		// opaque; a call inside assembly is not detected, but note the region
	}
}

func (s *flowScan) read(e sol.Expr) {
	if s.ctx.isStateRead(e) {
		s.cb(flowEvent{kind: evRead, pos: e.Pos(), target: e})
	}
}

func (s *flowScan) write(target sol.Expr, how string) {
	desc := describeTarget(s.ctx, target)
	s.cb(flowEvent{kind: evWrite, pos: target.Pos(), writeDesc: desc, target: target})
}

// expr walks an expression in evaluation order, reporting calls and writes.
func (s *flowScan) expr(e sol.Expr) {
	if e == nil {
		return
	}
	switch x := e.(type) {
	case *sol.AssignExpr:
		// RHS first, then LHS sub-expressions, then the store
		s.expr(x.R)
		s.expr(x.L)
		if ctx := s.ctx; ctx.isStateMutation(x.L) {
			how := "assign"
			if x.Op != "=" {
				how = x.Op
			}
			s.write(x.L, how)
		}
	case *sol.CallExpr:
		// arguments first
		for _, a := range x.Args {
			s.expr(a)
		}
		for _, o := range x.Opts {
			s.expr(o.Val)
		}
		// then the target expression's sub-parts
		s.exprNoCall(x.Fn)
		// push/pop mutate state instead of calling out
		if s.ctx.isStateMutation(x) {
			s.write(x, "push/pop")
			return
		}
		ck, desc := s.ctx.classifyCall(x)
		if ck == callNone {
			return
		}
		pc := pendingCall{pos: x.Pos(), kind: string(ck), desc: desc}
		s.calls = append(s.calls, pc)
		s.cb(flowEvent{kind: evCall, pos: x.Pos(), call: x, ck: ck, desc: desc})
	case *sol.IndexExpr:
		s.expr(x.X)
		s.expr(x.Index)
		s.read(x)
	case *sol.UnaryExpr:
		s.expr(x.X)
		if x.Op == "delete" && s.ctx.isStateMutation(x.X) {
			s.write(x.X, "delete")
		}
	case *sol.BinaryExpr:
		s.expr(x.L)
		s.expr(x.R)
	case *sol.TernaryExpr:
		s.expr(x.Cond)
		s.expr(x.Then)
		s.expr(x.Else)
	case *sol.TupleExpr:
		for _, it := range x.Items {
			s.expr(it)
		}
	case *sol.ArrayLitExpr:
		for _, it := range x.Items {
			s.expr(it)
		}
	case *sol.Ident:
		s.read(x)
	case *sol.MemberExpr:
		s.expr(x.X)
		s.read(x)
	case *sol.NewExpr, *sol.Literal, *sol.TypeExpr:
	}
}

// exprNoCall walks the receiver of a call without re-registering the call.
func (s *flowScan) exprNoCall(e sol.Expr) {
	switch x := e.(type) {
	case *sol.MemberExpr:
		s.exprNoCall(x.X)
	case *sol.IndexExpr:
		s.expr(x.X)
		s.expr(x.Index)
	case *sol.CallExpr:
		for _, a := range x.Args {
			s.expr(a)
		}
		s.exprNoCall(x.Fn)
		// nested call like f().g() — the inner call is still an external call
		if ck, desc := s.ctx.classifyCall(x); ck != callNone {
			pc := pendingCall{pos: x.Pos(), kind: string(ck), desc: desc}
			s.calls = append(s.calls, pc)
			s.cb(flowEvent{kind: evCall, pos: x.Pos(), call: x, ck: ck, desc: desc})
		}
	}
}

// ---- call classification ----

type callKind string

const (
	callNone          callKind = ""
	callLowLevel      callKind = "low-level"
	callDelegate      callKind = "delegatecall"
	callValueTransfer callKind = "value-transfer"
	callHighLevel     callKind = "external-contract"
	callSelf          callKind = "self"
	callInternal      callKind = "internal"
)

var lowLevelNames = map[string]bool{"call": true, "staticcall": true, "callcode": true, "delegatecall": true}

// classifyCall decides whether a call leaves the contract.
func (ctx *fnCtx) classifyCall(c *sol.CallExpr) (callKind, string) {
	switch fn := c.Fn.(type) {
	case *sol.Ident:
		name := fn.Name
		if name == "" {
			return callNone, ""
		}
		if builtinFn(name) || ctx.isProjectContractFn(name) {
			return callNone, ""
		}
		// an internal function or a local function-typed variable
		return callInternal, name
	case *sol.MemberExpr:
		name := fn.Name
		recv := fn.X
		recvType := ctx.exprType(recv)
		label := recvType
		if label == "" {
			label = exprText(recv)
		}
		switch {
		case name == "delegatecall" || name == "callcode":
			return callDelegate, label + "." + name
		case lowLevelNames[name]:
			return callLowLevel, label + "." + name
		case name == "transfer" || name == "send":
			// address payable transfer/send pass only 2300 gas, which cannot
			// re-enter meaningfully. token.transfer(to, amount) is a different
			// function and does call out.
			if isAddressType(typeWord(recvType)) || isPayableCast(recv) {
				return callValueTransfer, label + "." + name
			}
			return callHighLevel, label + "." + name
		}
		// `this.f()` is an external self-call
		if id, ok := recv.(*sol.Ident); ok && id.Name == "this" {
			return callSelf, "this." + name
		}
		if id, ok := recv.(*sol.Ident); ok && id.Name == "super" {
			return callInternal, "super." + name
		}
		// receiver is a contract-typed variable, a cast, or a state var
		if isExternalReceiver(ctx, recv, recvType) {
			return callHighLevel, label + "." + name
		}
		// library call via `using for` or explicit library name
		if ctx.a.prog.Libraries[recvType] {
			return callInternal, recvType + "." + name
		}
		if ctx.a.prog.Contracts[recvType] != nil && !ctx.a.prog.Interfaces[recvType] {
			return callInternal, recvType + "." + name
		}
		// unknown receiver: treat as external (e.g. a struct field holding a token)
		if isLikelyExternal(typeWord(recvType)) {
			return callHighLevel, label + "." + name
		}
		return callNone, ""
	case *sol.CallExpr:
		// chained call, e.g. IERC20(t).transfer(...)
		ck, _ := ctx.classifyCall(fn)
		if ck == callNone {
			return callNone, ""
		}
		return ck, ctx.exprType(c)
	}
	return callNone, ""
}

func isExternalReceiver(ctx *fnCtx, recv sol.Expr, recvType string) bool {
	if id, ok := recv.(*sol.Ident); ok {
		if _, isLocal := ctx.locals[id.Name]; !isLocal {
			if _, isState := ctx.state[id.Name]; isState {
				return true
			}
		}
		// a local holding a contract type
		if t, ok := ctx.locals[id.Name]; ok {
			return isExternalTypeWord(typeWord(t))
		}
	}
	if me, ok := recv.(*sol.MemberExpr); ok {
		// s.token / cfg.router — struct field holding an address
		if strings.Contains(strings.ToLower(me.Name), "token") || strings.Contains(strings.ToLower(me.Name), "router") ||
			strings.Contains(strings.ToLower(me.Name), "vault") || strings.Contains(strings.ToLower(me.Name), "pool") {
			return true
		}
	}
	if _, ok := recv.(*sol.CallExpr); ok {
		return true
	}
	return isExternalTypeWord(typeWord(recvType))
}

// isPayableCast reports `payable(x)` / `address(x)` receivers.
func isPayableCast(e sol.Expr) bool {
	c, ok := e.(*sol.CallExpr)
	if !ok || len(c.Args) != 1 {
		return false
	}
	switch fn := c.Fn.(type) {
	case *sol.Ident:
		return fn.Name == "payable" || fn.Name == "address"
	case *sol.TypeExpr:
		return fn.Name == "payable" || fn.Name == "address"
	}
	return false
}

func isAddressType(w string) bool {
	l := strings.ToLower(strings.TrimSpace(w))
	return l == "address" || strings.HasPrefix(l, "address ")
}

func isExternalTypeWord(w string) bool {
	if w == "" {
		return false
	}
	l := strings.ToLower(w)
	if l == "address" || strings.HasPrefix(l, "address") {
		return true
	}
	// IERC20, IPool, IUniswapV2Router — interface naming convention
	if strings.HasPrefix(w, "I") && len(w) > 1 && w[1] >= 'A' && w[1] <= 'Z' {
		return true
	}
	return false
}

// builtinFn is a compiler-provided function that never leaves the contract.
func builtinFn(name string) bool {
	switch name {
	case "require", "assert", "revert", "keccak256", "sha256", "ripemd160",
		"ecrecover", "addmod", "mulmod", "blockhash", "gasleft", "abi",
		"type", "selfdestruct", "suicide", "msg", "tx", "block", "payable":
		return true
	}
	return false
}

// isProjectContractFn reports whether name is a function defined in one of the
// analyzed contracts/libraries, i.e. an internal call.
func (ctx *fnCtx) isProjectContractFn(name string) bool {
	return len(ctx.a.fnIndex[name]) > 0
}

func isLikelyExternal(w string) bool {
	return w != "" && (isExternalTypeWord(w) || strings.HasSuffix(strings.ToLower(w), "contract"))
}

// typeWord extracts the head type name from a type string like
// "mapping(address => uint256)" or "IERC20".
func typeWord(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if strings.HasPrefix(t, "mapping(") {
		return ""
	}
	if i := strings.IndexAny(t, "[ "); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, "."); i >= 0 {
		t = t[i+1:]
	}
	return t
}

// exprType is a best-effort type inference for receivers.
func (ctx *fnCtx) exprType(e sol.Expr) string {
	switch x := e.(type) {
	case *sol.Ident:
		if t, ok := ctx.locals[x.Name]; ok {
			return t
		}
		if sv, ok := ctx.state[x.Name]; ok {
			return sv.Type
		}
		if ctx.a.prog.Contracts[x.Name] != nil {
			return x.Name
		}
		return ""
	case *sol.TypeExpr:
		return x.Name
	case *sol.CallExpr:
		// cast: IERC20(addr) / address(x) / payable(x)
		if fn, ok := x.Fn.(*sol.TypeExpr); ok {
			return fn.Name
		}
		if fn, ok := x.Fn.(*sol.Ident); ok {
			if len(x.Args) == 1 {
				if _, isVar := ctx.locals[fn.Name]; !isVar {
					return fn.Name
				}
			}
		}
		if fn, ok := x.Fn.(*sol.MemberExpr); ok {
			return ctx.exprType(fn.X)
		}
		return ""
	case *sol.MemberExpr:
		// this.x
		if id, ok := x.X.(*sol.Ident); ok && id.Name == "this" {
			if sv, ok := ctx.state[x.Name]; ok {
				return sv.Type
			}
		}
		// struct field type: look up if we can
		if base := ctx.exprType(x.X); base != "" {
			if t, ok := ctx.fieldType(base, x.Name); ok {
				return t
			}
		}
		return ""
	case *sol.IndexExpr:
		t := ctx.exprType(x.X)
		if strings.HasPrefix(t, "mapping(") {
			// value type after =>
			if i := strings.Index(t, "=>"); i >= 0 {
				v := strings.TrimSuffix(t[i+2:], ")")
				return strings.TrimSpace(v)
			}
		}
		if i := strings.Index(t, "["); i >= 0 {
			return strings.TrimSpace(t[:i])
		}
		return t
	case *sol.UnaryExpr:
		return ctx.exprType(x.X)
	}
	return ""
}

// fieldType resolves a struct field within a contract.
func (ctx *fnCtx) fieldType(structName, field string) (string, bool) {
	if ctx.contract == nil {
		return "", false
	}
	for _, m := range ctx.contract.Members {
		if sd, ok := m.(*sol.StructDef); ok && sd.Name == structName {
			for _, fl := range sd.Fields {
				if fl.Name == field {
					return fl.Type, true
				}
			}
		}
	}
	return "", false
}

// isSuccessCheck reports `require(ok)` / `assert(ok)` on a bare bool variable,
// which reverts the transaction when a prior call failed.
func (ctx *fnCtx) isSuccessCheck(e sol.Expr) bool {
	c, ok := e.(*sol.CallExpr)
	if !ok || len(c.Args) == 0 {
		return false
	}
	id, ok := c.Fn.(*sol.Ident)
	if !ok || (id.Name != "require" && id.Name != "assert") {
		return false
	}
	cond := c.Args[0]
	if b, ok := cond.(*sol.Ident); ok && isBoolName(b.Name) {
		return true
	}
	// require(ok && ...)
	if bin, ok := cond.(*sol.BinaryExpr); ok && bin.Op == "&&" {
		if b, ok := bin.L.(*sol.Ident); ok && isBoolName(b.Name) {
			return true
		}
	}
	return false
}

func isBoolName(n string) bool {
	l := n
	return l == "ok" || l == "success" || l == "sent" || l == "success_" || strings.HasPrefix(l, "ok") || strings.HasPrefix(l, "success")
}

// isStateRead reports whether an expression reads a contract state variable.
func (ctx *fnCtx) isStateRead(e sol.Expr) bool {
	switch x := e.(type) {
	case *sol.Ident:
		_, ok := ctx.state[x.Name]
		return ok
	case *sol.MemberExpr:
		if id, ok := x.X.(*sol.Ident); ok && id.Name == "this" {
			_, ok := ctx.state[x.Name]
			return ok
		}
		return false
	case *sol.IndexExpr:
		return ctx.isStateRead(x.X)
	}
	return false
}

// isStateMutation reports whether an expression stores into contract state.
func (ctx *fnCtx) isStateMutation(e sol.Expr) bool {
	switch x := e.(type) {
	case *sol.Ident:
		if ctx.consts[x.Name] {
			return false
		}
		_, ok := ctx.state[x.Name]
		return ok
	case *sol.IndexExpr:
		return ctx.isStateMutation(x.X)
	case *sol.MemberExpr:
		if id, ok := x.X.(*sol.Ident); ok && id.Name == "this" {
			return true
		}
		// member of a state struct/array element
		return ctx.isStateMutation(x.X)
	case *sol.TupleExpr:
		for _, it := range x.Items {
			if ctx.isStateMutation(it) {
				return true
			}
		}
		return false
	case *sol.CallExpr:
		// arr.push(...) / arr.pop()
		if me, ok := x.Fn.(*sol.MemberExpr); ok {
			if me.Name == "push" || me.Name == "pop" {
				return ctx.isStateMutation(me.X)
			}
		}
		return false
	case *sol.UnaryExpr:
		return ctx.isStateMutation(x.X)
	}
	return false
}

// describeTarget renders "balances[msg.sender]" style text for a target.
func describeTarget(ctx *fnCtx, e sol.Expr) string {
	switch x := e.(type) {
	case *sol.Ident:
		return x.Name
	case *sol.MemberExpr:
		return describeTarget(ctx, x.X) + "." + x.Name
	case *sol.IndexExpr:
		return describeTarget(ctx, x.X) + "[…]"
	case *sol.CallExpr:
		if me, ok := x.Fn.(*sol.MemberExpr); ok {
			return describeTarget(ctx, me.X)
		}
		return "state"
	}
	return "state"
}

// stateVarOf finds the root state variable of a target expression.
func (ctx *fnCtx) stateVarOf(e sol.Expr) (*sol.StateVar, bool) {
	switch x := e.(type) {
	case *sol.Ident:
		sv, ok := ctx.state[x.Name]
		return sv, ok
	case *sol.IndexExpr:
		return ctx.stateVarOf(x.X)
	case *sol.MemberExpr:
		return ctx.stateVarOf(x.X)
	}
	return nil, false
}

// ---- guarded detection ----

func modifierLooksLikeGuard(fn *sol.Func) bool {
	n := strings.ToLower(fn.Name)
	for _, k := range []string{"nonreentrant", "noreentrant", "reentrancyguard", "mutex", "nolock"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	if fn.Body != nil && len(fn.Body.Stmts) > 0 {
		// a require/revert on a state flag
		hasReq := false
		hasSet := false
		walkSimple(fn.Body.Stmts, func(st sol.Stmt) {
			switch s := st.(type) {
			case *sol.ExprStmt:
				if c, ok := s.X.(*sol.CallExpr); ok {
					if id, ok := c.Fn.(*sol.Ident); ok && (id.Name == "require" || id.Name == "revert" || strings.HasSuffix(id.Name, "require")) {
						hasReq = true
					}
				}
				if a, ok := s.X.(*sol.AssignExpr); ok {
					if id, ok := a.L.(*sol.Ident); ok && looksLikeLockVar(id.Name) {
						hasSet = true
					}
				}
			}
		})
		if hasReq && hasSet {
			return true
		}
	}
	return false
}

func looksLikeLockVar(n string) bool {
	l := strings.ToLower(n)
	for _, k := range []string{"status", "lock", "entered", "mutex", "guard", "_status"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// detectGuard decides whether a function is protected against reentrancy.
func (a *analyzer) detectGuard(c *sol.Contract, fn *sol.Func) (bool, string) {
	for _, mi := range fn.Modifiers {
		name := mi.Name
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:]
		}
		if a.guardMods[c] != nil && a.guardMods[c][name] {
			return true, "modifier " + name
		}
		if modifierNameLooksGuard(name) {
			return true, "modifier " + name
		}
		// inherited guard: look across all contracts
		for _, cc := range a.prog.Contracts {
			for _, m := range cc.Members {
				if f, ok := m.(*sol.Func); ok && f.Kind == "modifier" && f.Name == name && modifierLooksLikeGuard(f) {
					return true, "modifier " + name
				}
			}
		}
	}
	return false, ""
}

func modifierNameLooksGuard(n string) bool {
	l := strings.ToLower(n)
	for _, k := range []string{"nonreentrant", "noreentrant", "reentrancyguard", "lock", "mutex", "nested"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// walkSimple visits statements recursively (no path analysis).
func walkSimple(list []sol.Stmt, f func(sol.Stmt)) {
	var rec func(st sol.Stmt)
	rec = func(st sol.Stmt) {
		if st == nil {
			return
		}
		f(st)
		switch s := st.(type) {
		case *sol.Block:
			for _, x := range s.Stmts {
				rec(x)
			}
		case *sol.IfStmt:
			rec(s.Then)
			rec(s.Else)
		case *sol.ForStmt:
			rec(s.Init)
			rec(s.Body)
			rec(s.Post)
		case *sol.WhileStmt:
			rec(s.Body)
		case *sol.DoWhileStmt:
			rec(s.Body)
		case *sol.UncheckedStmt:
			rec(s.Body)
		case *sol.TryStmt:
			rec(s.Body)
			for _, c := range s.Catch {
				rec(c)
			}
		}
	}
	for _, st := range list {
		rec(st)
	}
}

// walkExprs visits every expression in a statement list.
func walkExprs(list []sol.Stmt, f func(e sol.Expr)) {
	walkSimple(list, func(st sol.Stmt) {
		switch s := st.(type) {
		case *sol.IfStmt:
			walkExpr(s.Cond, f)
		case *sol.ForStmt:
			if s.Cond != nil {
				walkExpr(s.Cond, f)
			}
		case *sol.WhileStmt:
			walkExpr(s.Cond, f)
		case *sol.DoWhileStmt:
			walkExpr(s.Cond, f)
		case *sol.ReturnStmt:
			walkExpr(s.Value, f)
		case *sol.EmitStmt:
			if s.Call != nil {
				walkExpr(s.Call, f)
			}
		case *sol.RevertStmt:
			if s.Call != nil {
				walkExpr(s.Call, f)
			}
		case *sol.ExprStmt:
			walkExpr(s.X, f)
		case *sol.VarDecl:
			walkExpr(s.Init, f)
		case *sol.TupleDecl:
			walkExpr(s.Init, f)
		case *sol.DeleteStmt:
			walkExpr(s.X, f)
		case *sol.TryStmt:
			if s.Call != nil {
				walkExpr(s.Call, f)
			}
		}
	})
}

func walkExpr(e sol.Expr, f func(e sol.Expr)) {
	if e == nil {
		return
	}
	f(e)
	switch x := e.(type) {
	case *sol.AssignExpr:
		walkExpr(x.L, f)
		walkExpr(x.R, f)
	case *sol.CallExpr:
		walkExpr(x.Fn, f)
		for _, a := range x.Args {
			walkExpr(a, f)
		}
		for _, o := range x.Opts {
			walkExpr(o.Val, f)
		}
	case *sol.MemberExpr:
		walkExpr(x.X, f)
	case *sol.IndexExpr:
		walkExpr(x.X, f)
		walkExpr(x.Index, f)
	case *sol.UnaryExpr:
		walkExpr(x.X, f)
	case *sol.BinaryExpr:
		walkExpr(x.L, f)
		walkExpr(x.R, f)
	case *sol.TernaryExpr:
		walkExpr(x.Cond, f)
		walkExpr(x.Then, f)
		walkExpr(x.Else, f)
	case *sol.TupleExpr:
		for _, it := range x.Items {
			walkExpr(it, f)
		}
	case *sol.ArrayLitExpr:
		for _, it := range x.Items {
			walkExpr(it, f)
		}
	}
}
