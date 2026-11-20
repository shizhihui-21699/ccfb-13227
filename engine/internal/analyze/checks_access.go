package analyze

import (
	"fmt"
	"strings"

	"solrecon/internal/sol"
)

// accessRule: state-changing entry points without any caller restriction.
//
// The rule fires when a reachable function mutates contract-wide
// administrative state (owner / fee / oracle / pause …) and nothing in the
// function or its modifiers establishes who the caller is. Writes into the
// caller's own slot (balances[msg.sender]) are deliberately not treated as
// privileged state.
func (a *analyzer) checkAccess(ctx *fnCtx) {
	fn := ctx.fn
	if fn == nil || fn.Body == nil {
		return
	}
	switch fn.Kind {
	case "receive", "fallback", "constructor", "modifier":
		return
	}
	if fn.Vis == "internal" || fn.Vis == "private" {
		return
	}
	if fn.Mutability == "view" || fn.Mutability == "pure" {
		return
	}
	if hasAccessModifier(ctx, fn) {
		return
	}
	configWrite, callerSlotOnly := classifyWrites(ctx, fn)
	if !configWrite {
		// Either nothing sensitive is written, or the only sensitive writes
		// land in the caller's own slot — normal user flow, not a privilege
		// boundary.
		if callerSlotOnly {
			return
		}
		return
	}
	name := fnLabel(fn)
	ctx.emit(findingOpts{
		rule:       "ACCESS-01",
		category:   CatAccess,
		severity:   SevHigh,
		title:      "敏感状态变更函数缺少权限限制",
		pos:        fn.Pos,
		endLine:    fn.Pos.Line,
		message:    fmt.Sprintf("%s 是 %s 函数且没有 owner/admin 修饰符或 msg.sender 校验，却会修改合约级关键状态。任何地址都能调用它。", name, visLabel(fn.Vis)),
		exploit:    fmt.Sprintf("攻击者直接调用 %s。由于没有调用者校验，攻击者可以把它指向自己（如把受益地址设为自己）、把费率改成 0 或极大值、暂停合约，或接管 owner 权限，然后取走资金或让其他用户无法使用。若与合约中其他“信任 owner”的函数组合，可直接升级为完全接管。", name),
		fix:        "加 onlyOwner / onlyRole(ADMIN) 修饰符，或在函数体内 `require(msg.sender == owner, \"not owner\");`；对初始化函数加 `initializer` 与 `require(owner == address(0))` 防重复初始化；优先使用 OpenZeppelin 的 AccessControl。",
		confidence: "medium",
	})
}

// classifyWrites inspects the function's stores and reports (a) whether a
// contract-wide sensitive slot is written, and (b) whether sensitive writes
// exist at all but are confined to msg.sender-keyed slots.
func classifyWrites(ctx *fnCtx, fn *sol.Func) (configWrite, callerSlotOnly bool) {
	sawSensitive := false
	sawConfig := false
	sawOther := false
	note := func(target sol.Expr) {
		sv, ok := ctx.stateVarOf(target)
		if !ok {
			return
		}
		if !sensitiveVar(sv.Name) {
			return
		}
		sawSensitive = true
		if ctx.writesContractSlot(sv, target) {
			sawConfig = true
		} else {
			sawOther = true
		}
	}
	walkSimple(fn.Body.Stmts, func(st sol.Stmt) {
		switch s := st.(type) {
		case *sol.ExprStmt:
			switch x := s.X.(type) {
			case *sol.AssignExpr:
				note(x.L)
			case *sol.CallExpr:
				if me, ok := x.Fn.(*sol.MemberExpr); ok && (me.Name == "push" || me.Name == "pop") {
					note(me.X)
				}
			}
		case *sol.DeleteStmt:
			note(s.X)
		}
	})
	return sawConfig, sawSensitive && sawOther && !sawConfig
}

func visLabel(v string) string {
	if v == "" {
		return "默认可见"
	}
	return v
}

var accessModRe = []string{
	"onlyowner", "onlyadmin", "onlyrole", "onlygovernance", "onlygovernor",
	"onlydao", "onlyoperator", "onlymanager", "onlykeeper", "auth", "requiresauth",
	"onlyminter", "onlyauthorized", "admin", "restricted", "onlymultisig", "onlytimelock",
}

func hasAccessModifier(ctx *fnCtx, fn *sol.Func) bool {
	for _, mi := range fn.Modifiers {
		n := strings.ToLower(strings.TrimSpace(mi.Name))
		if i := strings.LastIndex(n, "."); i >= 0 {
			n = n[i+1:]
		}
		for _, k := range accessModRe {
			if strings.Contains(n, k) {
				return true
			}
		}
	}
	// custom modifier bodies that check msg.sender
	for _, mi := range fn.Modifiers {
		if ctx.contract == nil {
			continue
		}
		if modChecksSender(ctx.a, ctx.contract, mi.Name) {
			return true
		}
	}
	// inline checks in the first statements
	checked := false
	n := 0
	for _, st := range fn.Body.Stmts {
		if n >= 6 {
			break
		}
		n++
		if stmtMentionsSenderGuard(st) {
			checked = true
			break
		}
	}
	return checked
}

func modChecksSender(a *analyzer, c *sol.Contract, name string) bool {
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	seen := map[*sol.Func]bool{}
	var search func(c *sol.Contract) bool
	search = func(c *sol.Contract) bool {
		for _, m := range c.Members {
			f, ok := m.(*sol.Func)
			if !ok || f.Kind != "modifier" || f.Name != name || f.Body == nil || seen[f] {
				continue
			}
			seen[f] = true
			found := false
			walkSimple(f.Body.Stmts, func(st sol.Stmt) {
				if found {
					return
				}
				if stmtMentionsSenderGuard(st) {
					found = true
				}
			})
			if found {
				return true
			}
		}
		// walk inherited contracts
		for _, b := range c.Bases {
			if bc := a.prog.Contracts[b]; bc != nil && search(bc) {
				return true
			}
		}
		return false
	}
	return search(c)
}

func stmtMentionsSenderGuard(st sol.Stmt) bool {
	hit := false
	switch s := st.(type) {
	case *sol.IfStmt:
		// `if (msg.sender != owner) revert;` is a guard
		if exprMentions(s.Cond, "msg.sender") || exprMentions(s.Cond, "_msgSender") {
			hit = true
		}
	case *sol.ExprStmt:
		if c, ok := s.X.(*sol.CallExpr); ok {
			if id, ok := c.Fn.(*sol.Ident); ok {
				switch id.Name {
				case "require", "assert":
					if len(c.Args) > 0 && (exprMentions(c.Args[0], "msg.sender") || exprMentions(c.Args[0], "_msgSender") || exprMentions(c.Args[0], "tx.origin")) {
						hit = true
					}
				}
			}
		}
	case *sol.RevertStmt:
		if s.Call != nil && len(s.Call.Args) > 0 && exprMentions(s.Call.Args[0], "msg.sender") {
			hit = true
		}
	}
	return hit
}

func exprMentions(e sol.Expr, path string) bool {
	found := false
	walkExpr(e, func(x sol.Expr) {
		if found {
			return
		}
		if text := flatText(x); text == path {
			found = true
		}
	})
	return found
}

// flatText renders a short member chain, e.g. msg.sender.
func flatText(e sol.Expr) string {
	switch x := e.(type) {
	case *sol.Ident:
		return x.Name
	case *sol.MemberExpr:
		base := flatText(x.X)
		if base == "" {
			return ""
		}
		return base + "." + x.Name
	}
	return ""
}

// privilegedStateWords name contract-wide administrative state. Per-user
// bookkeeping (balances, shares, rewards) is deliberately absent: an arbitrary
// caller writing their own slot is normal user flow, not a privilege boundary.
var privilegedStateWords = []string{
	"owner", "admin", "govern", "fee", "rate", "price", "oracle", "router",
	"treasury", "beneficiar", "operator", "minter", "paus", "impl", "logic",
	"whitelist", "blacklist", "guardian", "controller", "manager", "signer",
	"threshold", "cap", "total", "delegate", "role", "authority", "config",
}

// writesWholeState reports whether the assignment target is the state variable
// itself or an element keyed by msg.sender (a user writing their own slot),
// as opposed to a global/admin-controlled slot.
func (ctx *fnCtx) writesContractSlot(sv *sol.StateVar, target sol.Expr) bool {
	switch t := target.(type) {
	case *sol.Ident:
		return t.Name == sv.Name && sv.Name != ""
	case *sol.IndexExpr:
		if ctx.writesContractSlot(sv, t.X) {
			return !isSenderKey(t.Index)
		}
		return ctx.writesContractSlot(sv, t.X)
	case *sol.MemberExpr:
		return ctx.writesContractSlot(sv, t.X)
	}
	return true
}

func isSenderKey(e sol.Expr) bool {
	s := flatText(e)
	return s == "msg.sender" || s == "_msgSender()" || s == "tx.origin"
}

func sensitiveVar(name string) bool {
	l := strings.ToLower(name)
	for _, w := range privilegedStateWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}
