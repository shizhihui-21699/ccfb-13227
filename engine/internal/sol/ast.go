package sol

// Pos is a source position. Line and Col are 1-based; Off is a byte offset.
type Pos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
	Off  int `json:"off"`
}

func (p Pos) IsZero() bool { return p.Line == 0 }

// Diag is a lex/parse diagnostic. It is reported, never fatal.
type Diag struct {
	Line int    `json:"line"`
	Col  int    `json:"col"`
	Msg  string `json:"message"`
}

// Source is a parsed Solidity source file.
type Source struct {
	Contracts   []*Contract
	Functions   []*Func // free functions (file level)
	Pragma      string
	PragmaLine  int
	Imports     []string
	Diagnostics []Diag
}

// Contract is a contract, interface, library, or abstract contract.
type Contract struct {
	Name     string
	Kind     string // contract | interface | library
	Abstract bool
	Bases    []string
	Members  []Member
	Pos      Pos
}

type Member interface{ memberNode() }

// StateVar is a contract-level variable.
type StateVar struct {
	Name      string
	Type      string
	Vis       string
	Constant  bool
	Immutable bool
	Init      Expr
	Pos       Pos
}

func (*StateVar) memberNode() {}

type StructDef struct {
	Name   string
	Fields []Param
	Pos    Pos
}

func (*StructDef) memberNode() {}

type EnumDef struct {
	Name   string
	Values []string
	Pos    Pos
}

func (*EnumDef) memberNode() {}

type EventDef struct {
	Name   string
	Params []Param
	Pos    Pos
}

func (*EventDef) memberNode() {}

type ErrorDef struct {
	Name   string
	Params []Param
	Pos    Pos
}

func (*ErrorDef) memberNode() {}

type UsingDef struct {
	Pos Pos
}

func (*UsingDef) memberNode() {}

// Func covers functions, constructors, receive/fallback, and modifiers.
type Func struct {
	Name       string
	Kind       string // function | constructor | receive | fallback | modifier
	Vis        string
	Mutability string
	Virtual    bool
	Params     []Param
	Returns    []Param
	Modifiers  []ModifierInvoke
	Body       *Block
	Pos        Pos
	Contract   *Contract
}

func (*Func) memberNode() {}

type ModifierInvoke struct {
	Name string
	Args []Expr
	Pos  Pos
}

type Param struct {
	Name string
	Type string
	Pos  Pos
}

// ---- Statements ----

type Stmt interface{ Pos() Pos }

type Block struct {
	Stmts []Stmt
	Posv  Pos
}

func (s *Block) Pos() Pos { return s.Posv }

type IfStmt struct {
	Cond Expr
	Then Stmt
	Else Stmt
	Posv Pos
}

func (s *IfStmt) Pos() Pos { return s.Posv }

type ForStmt struct {
	Init Stmt
	Cond Expr
	Post Stmt
	Body Stmt
	Posv Pos
}

func (s *ForStmt) Pos() Pos { return s.Posv }

type WhileStmt struct {
	Cond Expr
	Body Stmt
	Posv Pos
}

func (s *WhileStmt) Pos() Pos { return s.Posv }

type DoWhileStmt struct {
	Body Stmt
	Cond Expr
	Posv Pos
}

func (s *DoWhileStmt) Pos() Pos { return s.Posv }

type ReturnStmt struct {
	Value Expr
	Posv  Pos
}

func (s *ReturnStmt) Pos() Pos { return s.Posv }

type EmitStmt struct {
	Call *CallExpr
	Posv Pos
}

func (s *EmitStmt) Pos() Pos { return s.Posv }

type RevertStmt struct {
	Call *CallExpr
	Posv Pos
}

func (s *RevertStmt) Pos() Pos { return s.Posv }

type ExprStmt struct {
	X    Expr
	Posv Pos
}

func (s *ExprStmt) Pos() Pos { return s.Posv }

// VarDecl is `uint256 x = ...` or `IERC20 token;`.
type VarDecl struct {
	Type string
	Name string
	Init Expr
	Posv Pos
}

func (s *VarDecl) Pos() Pos { return s.Posv }

// TupleDecl is `(bool ok, bytes memory data) = target.call(...)`.
type TupleDecl struct {
	Types []string
	Names []string
	Init  Expr
	Posv  Pos
}

func (s *TupleDecl) Pos() Pos { return s.Posv }

type UncheckedStmt struct {
	Body *Block
	Posv Pos
}

func (s *UncheckedStmt) Pos() Pos { return s.Posv }

// AssemblyStmt keeps the raw body; the analyzer treats it as opaque.
type AssemblyStmt struct {
	Raw  string
	Posv Pos
}

func (s *AssemblyStmt) Pos() Pos { return s.Posv }

type TryStmt struct {
	Call  *CallExpr
	Body  *Block
	Catch []*Block
	Posv  Pos
}

func (s *TryStmt) Pos() Pos { return s.Posv }

type BreakStmt struct{ Posv Pos }

func (s *BreakStmt) Pos() Pos { return s.Posv }

type ContinueStmt struct{ Posv Pos }

func (s *ContinueStmt) Pos() Pos { return s.Posv }

type DeleteStmt struct {
	X    Expr
	Posv Pos
}

func (s *DeleteStmt) Pos() Pos { return s.Posv }

// ---- Expressions ----

type Expr interface{ Pos() Pos }

type Ident struct {
	Name string
	Posv Pos
}

func (e *Ident) Pos() Pos { return e.Posv }

type Literal struct {
	Kind string // number | string | bool | hex
	Text string
	Posv Pos
}

func (e *Literal) Pos() Pos { return e.Posv }

type MemberExpr struct {
	X    Expr
	Name string
	Posv Pos
}

func (e *MemberExpr) Pos() Pos { return e.Posv }

type IndexExpr struct {
	X     Expr
	Index Expr
	Posv  Pos
}

func (e *IndexExpr) Pos() Pos { return e.Posv }

type CallExpr struct {
	Fn   Expr
	Args []Expr
	Opts []NamedArg
	Posv Pos
}

func (e *CallExpr) Pos() Pos { return e.Posv }

type NamedArg struct {
	Name string
	Val  Expr
}

type UnaryExpr struct {
	Op     string
	X      Expr
	Prefix bool
	Posv   Pos
}

func (e *UnaryExpr) Pos() Pos { return e.Posv }

type BinaryExpr struct {
	Op   string
	L, R Expr
	Posv Pos
}

func (e *BinaryExpr) Pos() Pos { return e.Posv }

type AssignExpr struct {
	Op   string
	L, R Expr
	Posv Pos
}

func (e *AssignExpr) Pos() Pos { return e.Posv }

type TernaryExpr struct {
	Cond, Then, Else Expr
	Posv             Pos
}

func (e *TernaryExpr) Pos() Pos { return e.Posv }

type TupleExpr struct {
	Items []Expr
	Posv  Pos
}

func (e *TupleExpr) Pos() Pos { return e.Posv }

type NewExpr struct {
	Type string
	Posv Pos
}

func (e *NewExpr) Pos() Pos { return e.Posv }

// TypeExpr is an elementary type used as an expression, e.g. uint8(x).
type TypeExpr struct {
	Name string
	Posv Pos
}

func (e *TypeExpr) Pos() Pos { return e.Posv }

type ArrayLitExpr struct {
	Items []Expr
	Posv  Pos
}

func (e *ArrayLitExpr) Pos() Pos { return e.Posv }
