# SolRecon 合约审查台

用 Go 写静态检查引擎，编译成 WebAssembly，在浏览器里直接解析 Solidity 源码并给出问题清单。所有分析都在本地完成，源码不会离开浏览器。

面向的场景：外包交付的合约，在送审之前先做一轮自查——把常见、可机械识别的坑先清掉，让真金白银的审计预算花在业务逻辑上。

## 跑起来

```bash
./build.sh                      # 跑测试 + 重编 wasm + 刷新内置样例
cd web && python3 -m http.server 8080
# 打开 http://localhost:8080
```

页面需要 `http://` 打开：`file://` 下浏览器会阻止 `fetch()` 加载 `audit.wasm`。页面对这种情况会给出明确提示。

也可以不开浏览器，用命令行跑同一套引擎：

```bash
cd engine
go run ./cmd/auditcli ../../samples/01-reentrancy/vulnerable/Bank.sol   # 人类可读
go run ./cmd/auditcli -json samples/                                   # 机器可读报告
go run ./cmd/auditcli -min high samples/                               # 只看高危
```

## 检查什么

十条规则，覆盖你点名的五类问题。

| 规则 | 类别 | 默认级别 | 判定方式 |
|---|---|---|---|
| `REENT-01` | 重入 | 高 | 按源码顺序走函数体，记录"可能已执行"的外部调用集合；之后出现状态写入即报告，并回溯是哪个调用打开的窗口 |
| `UNCHK-01` | 未检查返回值 | 高 | 表达式语句里结果被丢弃的 `call` / `delegatecall` / `send` / ERC20 `transfer` 等 |
| `UNCHK-02` | 未检查返回值 | 中 | `(bool ok, ) = x.call(...)` 声明了 `ok`，但函数内再未读取 |
| `ACCESS-01` | 权限 | 高 | 非 view 的公开函数写入 owner/fee/oracle/pause 等合约级状态，而修饰符、修饰符体、函数前几条语句里都没有 `msg.sender` 校验 |
| `RAND-01` | 随机数 | 高 | `block.timestamp` / `number` / `difficulty` / `prevrandao` / `coinbase` 参与取模、位运算，或作为 `keccak256` 的输入 |
| `INT-01` | 整数 | 中 | pragma 允许 `<0.8.0`，且对非常量做 `+ - * **`（旧版没有溢出检查） |
| `INT-02` | 整数 | 高 | `uint256 -> uint96/uint128/...` 等收窄转换，此前没有对该变量的上界 `require`/`if` 校验 |
| `INT-03` | 整数 | 提示 | `unchecked { }` 区块，提醒人工复核其中运算的输入范围 |
| `INT-04` | 整数 | 低 | 乘法链条里含除法（先除后乘导致系统性取整损失） |

除规则表外，每条报告都带四段内容：**问题**（在哪、为什么）、**怎么被利用**（具体攻击路径）、**怎么修**、**关联位置**（比如重入里实际写状态的那一行）。

引擎侧的关键设计：

- **路径敏感的调用窗口**：`if/else`、循环在汇合点对"可能已执行的调用"取并集，`return` 终止当前路径。所以 `if (c) { x.call(); } balances[a]=0;` 会被报告，而调用在两个互斥分支里各自先于写入则不会误报。
- **调用分类**：区分低级调用、`delegatecall`、`address.transfer/send`（2300 gas，不足以重入）、`this.f()` 外部自调用、接口/合约类型接收者的高级调用、库与内部函数。`require`、`keccak256`、`revert CustomError(...)`、`emit` 都不会被当成外部调用。
- **误报收敛**：调用后紧跟 `require(ok)` 时，重入降级为中危（失败会整体回滚，但仍存在检查-生效窗口）；`balances[msg.sender]` 这类用户自有槽位不算权限问题的敏感状态；构造函数不做权限检查；`block.timestamp >= deadline` 这种时间窗口不算随机数。

## 样例

`samples/` 下五组，每组 `vulnerable/` 与 `fixed/` 成对，同名文件、同样的业务逻辑，只差修法：

| 目录 | 场景 | 问题版命中 | 修复版 |
|---|---|---|---|
| `01-reentrancy` | 银行存取款 | 重入 ×2、未检查 ×2 | 0 |
| `02-unchecked` | ETH / ERC20 分发 | 重入 ×3、未检查 ×3 | 0 |
| `03-access` | 金库配置函数 | 权限 ×3 | 0 |
| `04-randomness` | 抽奖开奖 | 随机数 ×3 | 0（改为 commit-reveal） |
| `05-integer` | 代币计量 | 整数 ×3、权限 ×1 | 仅 1 条提示（`unchecked` 区块） |

`go test ./...` 会逐组断言：问题版必须命中指定规则、指定行号；修复版不得命中。这既是回归测试，也是"修复确实被识别为修复"的证明。

`engine/testdata/syntax/Kitchen.sol` 是一份刻意的语法大杂烩（interface / library / abstract / 继承 / struct / enum / mapping 嵌套 / try-catch / unchecked / assembly / 多重修饰符 / 结构体字面量 / 元组解构 / `{value, gas}` 调用），测试要求解析零告警。

## 语法覆盖

**完整支持**：contract / interface / library / abstract contract 与继承列表；状态变量（`public`/`constant`/`immutable`、初始化、mapping / 数组 / 结构体类型）；function / constructor / receive / fallback / modifier，含参数、返回值、可见性、mutability、修饰符调用；struct / enum / event / error / using-for；if-else / for / while / do-while / return / emit / revert / delete / try-catch / unchecked / 块作用域；赋值与复合赋值、三元、二元一元运算、成员访问、下标、调用（含 `{value, gas}`）、new、类型转换、元组、结构体字面量、数组字面量；`calldata`/`memory`/`storage`。多文件一起传入时会做跨文件合约索引。

**部分支持**：`assembly { }` 按不透明区块跳过（其中的调用与存储不分析）；函数类型变量按命名约定判断；mapping 深度嵌套与库函数返回的合约类型靠类型名启发式；Yul 对象、自定义 storage layout、transient storage 未覆盖。

**不在范围内**：不做符号执行、不追踪跨函数调用链（只看函数体内的源码顺序与路径并集）；不解析 import 指向的实际文件；不检查 ERC 标准一致性、Gas、代理存储布局。结论是静态启发式，会有误报漏报——**它筛掉的是显而易见的问题，不替代人工审计**。

解析器是手写的容错递归下降实现：遇到不认识的语法会跳过该声明并记一条解析提示（页面底部显示），不会让整份文件失败，已识别的部分照常分析。

## 结构

```
engine/
  internal/sol/       lexer、容错 parser、AST
  internal/analyze/   规则引擎、规则目录、测试
  cmd/auditcli/      命令行入口
  cmd/wasmaudit/     wasm 入口（暴露 window.solrecon.analyze）
  testdata/syntax/   语法覆盖夹具
web/                 index.html / app.js / app.css / highlight.js + 构建产物
samples/             五组成对样例
build.sh             一键构建
```

wasm 模块约 5.3 MiB（gzip 后约 1.5 MiB），首次加载后完全在浏览器内运行。
