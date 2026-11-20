package analyze

// Catalog returns the rule metadata shown in the UI.
func Catalog() []RuleMeta {
	return []RuleMeta{
		{
			ID: "REENT-01", Category: CatReentrancy, Severity: SevHigh,
			Title:   "外部调用后更新状态（重入）",
			Summary: "同一函数内先向外部地址发起调用，调用返回后才写入状态变量。",
			How:     "按源码顺序遍历函数体，记录“可能已执行”的外部调用集合（if/else、循环在汇合点取并集，return 终止路径）。之后每遇到状态写入，若集合非空即报告，并回溯是哪一个调用打开的窗口。",
		},
		{
			ID: "UNCHK-01", Category: CatUnchecked, Severity: SevHigh,
			Title:   "外部调用返回值被丢弃",
			Summary: "call/delegatecall/send/transfer 或 ERC20 转账的返回值没有进入 require/if。",
			How:     "识别表达式语句中直接丢弃的调用；对低级调用无条件报告，对 transfer/transferFrom/approve 等按接口声明或命名约定判断是否返回 bool，仅对返回 bool 的报告。",
		},
		{
			ID: "UNCHK-02", Category: CatUnchecked, Severity: SevMedium,
			Title:   "结果赋给变量但从未检查",
			Summary: "(bool ok, bytes data) = x.call(...) 之后 ok 从未被读取。",
			How:     "对元组声明的第一个 bool 变量做函数内使用分析，声明行之后没有任何引用即报告。",
		},
		{
			ID: "ACCESS-01", Category: CatAccess, Severity: SevHigh,
			Title:   "敏感状态变更缺少权限限制",
			Summary: "非 view 的 public/external 函数修改 owner/fee/oracle/余额类状态，却没有任何调用者校验。",
			How:     "先找 onlyOwner/onlyRole 等修饰符、再检查修饰符体内是否有 msg.sender 校验，最后看函数前 6 条语句是否含 require(msg.sender==...)。三者都没有、且写入了名字命中敏感词表的状态变量，即报告。",
		},
		{
			ID: "RAND-01", Category: CatRandom, Severity: SevHigh,
			Title:   "用区块属性作随机数",
			Summary: "block.timestamp/number/difficulty/prevrandao/coinbase 参与取模、比较或作为 keccak 的输入。",
			How:     "在二元运算（%、<、>、&、位移等）与 keccak256/abi.encodePacked 参数中查找区块属性链；命中即报告，并说明该属性的可操纵程度。",
		},
		{
			ID: "INT-01", Category: CatInteger, Severity: SevMedium,
			Title:   "0.8 之前的算术静默溢出",
			Summary: "pragma 允许 <0.8.0，且对非常量做 + - * ** 而没有 SafeMath。",
			How:     "解析 pragma 的最低版本；低于 0.8 时，遍历算术表达式，排除字面量常量与 unchecked 区域（旧版本没有 unchecked，因而全报）。",
		},
		{
			ID: "INT-02", Category: CatInteger, Severity: SevHigh,
			Title:   "收窄转换缺少上界检查",
			Summary: "uint256 -> uint96/uint128/uint8 等显式转换没有先 require 上界。",
			How:     "匹配单参数类型转换调用；比较目标位宽与源表达式类型位宽，目标更窄时，检查同一函数内此前是否有对该变量的 require/if 上界校验。",
		},
		{
			ID: "INT-03", Category: CatInteger, Severity: SevInfo,
			Title:   "unchecked 区块关闭溢出检查",
			Summary: "显式 unchecked { } 区域内的算术不做溢出检查。",
			How:     "收集 unchecked 语句覆盖的行区间，提示人工复核其中的运算输入是否受外部控制。",
		},
		{
			ID: "INT-04", Category: CatInteger, Severity: SevLow,
			Title:   "先除后乘造成精度丢失",
			Summary: "乘法表达式的一侧是除法链，整数取整导致系统性偏小。",
			How:     "在 `*` 节点下查找 `/`，命中即提示，建议改成先乘后除或 mulDiv。",
		},
	}
}

// Coverage documents, for the UI, what the parser handles.
func coverage() Coverage {
	return Coverage{
		Supported: []string{
			"contract / interface / library / abstract contract，含继承列表",
			"状态变量（含 public/constant/immutable、初始化表达式、mapping / 数组 / 结构体类型）",
			"函数、constructor、receive、fallback、modifier，含参数、返回值、可见性、mutability、修饰符调用",
			"struct / enum / event / error / using-for 声明",
			"语句：if/else、for、while、do-while、return、emit、revert、delete、try/catch、unchecked、块作用域",
			"表达式：赋值与复合赋值、三元、二元/一元运算、成员访问、下标、调用（含 {value,gas} 选项）、new、类型转换、元组、结构体字面量、数组字面量",
			"calldata/memory/storage 数据位置、多文件与跨文件继承索引",
		},
		Partial: []string{
			"内联汇编 assembly：识别为不透明区块，不分析其中的调用与存储",
			"函数类型变量与高阶调用：按类型名启发式判断是否外部调用",
			"复杂类型推导：mapping 嵌套、通过库函数返回的合约类型按命名约定判断",
			"Yul 对象、自定义 storage layout、transient storage 未覆盖",
		},
		NotCovered: []string{
			"不做数据流/符号执行，不追踪跨函数的调用链（仅按源码顺序与路径并集）",
			"不解析 import 指向的实际文件，跨文件符号按名字索引",
			"不检查 ERC 标准一致性、Gas 优化、升级代理存储布局（另有专项规则可扩展）",
			"不执行链上状态，结论为静态启发式，需人工复核误报",
		},
	}
}
