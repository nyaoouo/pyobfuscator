# pyobfuscator — 选项参考

所有混淆与保护参数均分布在
[`src/pyobfuscator/options.py`](../src/pyobfuscator/options.py) 中的两个数据类上：

- **`ObfOptions`** — 由 `obf_func` 使用；涵盖完整的混淆与保护功能面。
- **`ModuleObfOptions(ObfOptions)`** — 由 `obf_module` 使用；在此基础上增加了模块级选项（诱饵源码、蜜罐处理器、导出声明）。

```python
from pyobfuscator import obf_module, ModuleObfOptions
out = obf_module(src, ModuleObfOptions(output="text", seed=1, pack_body=True, key_from_cff=True))
```

以下约定适用于全文：

- **Effect（效果）** — 该标志对输出内容所做的改变。
- **Impact（影响）** — 代价与后果（产物大小、运行时开销、确定性、可移植性）。实测数据见 §15。
- **Limitations（限制）** — 前置条件、显式报错拒绝、假阳性风险及交互关系。

所有标志共同遵循两条全局性质：

- **确定性。** 相同的 `source + seed + flags` ⇒ 字节完全相同的输出。若 `seed=None`，则每次调用时随机抽取一个种子。
- **等价性门控。** 在未被篡改的路径上，混淆后的程序与原始程序行为完全一致（返回值、异常类型与消息、标准输出、参数变更）。引擎无法确定性保留的任何内容都会被显式报错拒绝（参见 `on_unsupported`）。

---

## 0. 构建期常量（`precompile` / `precompile_arg`）

`pyobfuscator` 顶层包导出的两个标记函数，可在**构建期**将计算结果作为字面常量折叠到混淆产物中。
两者在运行时均为恒等 / 返回默认值，因此未混淆的源码仍可正常运行。

```python
from pyobfuscator import precompile, precompile_arg, obf_module, ModuleObfOptions

def _scramble(text):
    return tuple((ord(c) + i * 3) % 256 for i, c in enumerate(text))

def license_ok(key):
    # 构建期：_scramble(LICENSE_KEY) 被求值；结果元组作为常量折叠进来。
    # 输出的常量侧不出现任何密钥字面量或 scramble 算法。
    return _scramble(key) == precompile(_scramble(precompile_arg("LICENSE_KEY")))

out = obf_module(src, ModuleObfOptions(
    precompile_args={"LICENSE_KEY": "PROD-KEY-1234"},
    const_archive=True,   # 折叠后的常量随即被加密
))
```

### `precompile(expr)`

构建期：混淆器对 `expr` 求值，并将 `precompile(...)` 调用替换为结果常量。折叠后的常量随即流经字面量混淆 Pass（`const_archive` / `obf_ints` / `obf_strings`）并被加密——输入值和所用算法均从产物中消失。

运行时：恒等函数（`return x`），未混淆的源码可正常运行。

**约束：** `expr` 必须在构建期可求值（模块级函数 / 导入 / 字面量——不能是函数参数）。结果必须是字面量可表示的值（见下方显式报错列表）。构建期求值在**隔离子进程**中运行（副作用和崩溃被隔离；子进程继承构建环境的 `sys.path`）。

### `precompile_arg(key[, default])`

构建期：替换为构建脚本在 `options.precompile_args[key]` 中注入的值（作为常量折叠），若 `key` 不存在则使用 `default`。

运行时：返回 `default`（若未提供则为 `None`），未混淆的源码使用开发默认值正常运行。

**必填与可选：**

- **单参数形式 `precompile_arg("KEY")`** — 必填：若 `"KEY"` 不在 `precompile_args` 中，构建将大声报错。使用此形式可将密钥完全限定在构建脚本中，源码中不会出现任何密钥信息。
- **双参数形式 `precompile_arg("KEY", default)`** — 可选：`"KEY"` 不存在时使用 `default`。注意 default 值会出现在源码中；若 default 也需隐藏，请使用单参数形式。

**有意为之的行为差异：** 当注入的构建值与 default 不同时，混淆产物的行为与明文源码的运行结果不同（运行时使用 default）。这是此功能的设计意图——注入生产密钥使混淆二进制使用生产值，明文源码则使用开发默认值。

支持嵌套组合：`precompile(_scramble(precompile_arg("KEY")))` 会在子进程 eval 内部解析 `precompile_arg`，外层 `precompile` 再折叠最终结果。

### `ObfOptions.precompile_args: dict`（默认 `{}`）

构建脚本注入的值，以字符串为键。值必须是字面量可表示的常量（与 `precompile` 结果的要求相同）。通过 `obf_func` / `obf_module` / `obf_project` 原样透传（它是 `ObfOptions` 的基类字段）。

### `ObfOptions.precompile_timeout: float`（默认 `30.0`）

build-eval 子进程的单元级超时（秒）。构建期计算较慢时调大；超时则构建 fail-loud。build-eval 结果按（模块源码 + 注入参数 + 表达式）在**进程内缓存**，所以同进程内的相同重建（确定性校验、只更新某模块的重建、`obf_project` 重跑）会复用结果而不再起子进程。

### 与加密的组合效果

`PrecompilePass` 在流水线中**最先**运行，早于所有字面量混淆 Pass。折叠后的常量随即被你所启用的 `const_archive` / `obf_ints` / `obf_strings` 加密。启用 `const_archive=True` 可获得最强效果（常量被汇入加密数据包）。

### 确定性

`precompile` 表达式应为**纯函数**（相同输入 → 相同输出）。非确定性表达式（如读取时间戳或随机值）会导致构建不可重现。此约束不做强制检查，由调用方负责。

### 显式报错条件

以下情况构建会抛出 `ValueError`：

| 条件 | 错误 |
|---|---|
| `expr` 引用了函数参数或其他模块作用域不可用的名称 | 子进程 eval 错误 |
| `precompile(...)` 的结果不是字面量可表示的值（如自定义类实例） | 结果验证错误 |
| `precompile` 的参数数量 ≠ 1 | 参数数量错误 |
| `precompile_arg` 的参数数量 ∉ {1, 2}，或 key 不是字符串字面量 | 验证错误 |
| `precompile_arg("KEY")`（单参数，必填）但 `"KEY"` 不在 `precompile_args` 中 | 缺少必要的构建参数 |
| `precompile_args` 中的值不是字面量可表示的常量 | 选项验证错误 |
| 子进程超时（> 30 秒） | 超时错误 |

---

## 1. 核心 / 输出

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `output` (`"pyc"`) | 输出格式：`"pyc"`（PEP-552 基于哈希、不校验、**无源码** 的 `.pyc` 字节流）、`"text"`（混淆后的源码字符串）、`"ast"`（一个 `ast.Module`）。 | `pyc` 体积紧凑，无需源文件即可运行；`text` 跨 Python 版本可移植；`ast` 用于后续程序化处理。 | `.pyc` 通过其魔数**锁定版本**（仅能在构建时所用 Python 版本上运行）。`output="ast"` 完全跳过打包器，因此 `pack_body`/`attest` 等选项无效。 |
| `seed` (`None`) | 所有随机化决策（状态 ID、名称最终化、密钥派生、RSA 参数）的随机种子。 | 控制可重现性。 | `None` ⇒ 每次调用使用全新随机种子 ⇒ 输出不可重现。如需可重现构建，请设置为整数。 |
| `strip_debug` (`False`) | 将所有 AST 源码位置重置为第 1 行 / 第 0 列。 | 从回溯信息中删除行号；产物略微缩小。 | 无。 |
| `on_unsupported` (`STRICT`) | 针对门控无法保留的语法结构的处理策略。`STRICT` 收集所有诊断信息后抛出异常，拒绝整个处理单元。 | 显式报错 — 绝不静默地输出错误转换结果。 | 目前仅实现了 `STRICT`；`REPORT`/`SKIP` 为保留值。 |
| `min_blocks` (`2`) | 跳过展平函数体基本块数少于此值的函数。 | 避免对没有实际控制流的平凡函数产生膨胀。 _实测（§15）：取值越大产物越小（如 `min_blocks=8` 时 12 KB → 8 KB）。_ | 低于阈值的函数将以未展平形式输出（仍受其他处理趟影响）。 |
| `max_block_stmts` (`None`) | 限制每个调度块的语句数上限；超出限制的块会拆分到多个状态中。 | 防止任意单一状态成为体积庞大、易于识别的特征。 | `None` = 不设上限。启动器展平时会默认应用 12 的上限。 |
| `emit_sourcemap` (`False`) | 将 JSON 反混淆映射写入调用方提供的 `sourcemap_out` 接收器。 | 仅在构建阶段生效；用于调试与审计。 | **绝不嵌入**产物中；无论是否开启，输出字节完全一致。需要在调用 `obf_*`/`emit` 时传入 `sourcemap_out=`。 |

---

## 2. 控制流平坦化（调度器结构）

核心变换将每个函数 / 方法 / 模块体转换为一个 `while True` 状态机调度器。以下标志用于调整该调度器的形态。所有选项均满足确定性与行为保持性。

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `safe_mode` (`True`) | `try/finally` 处理策略。`True` = 混合模式（保留真实的 `try/finally`）；`False` = 使用续延栈展开模型完全展平。 | `False` 将 finally 体展平得更深。 | `False` 会拒绝在 `finally` 块内出现 `return`/`break`/`continue`（显式报错）。 |
| `shuffle_states` (`True`) | 将调度器状态 ID 重映射为随机整数，并随机打乱守卫顺序。 | 消除顺序状态编号这一特征。 _实测（§15）：在运行噪声范围内。_ | 无。 |
| `opaque_predicates` (`True`) | 将跳转赋值包裹在恒为真的不透明谓词中（每个位置使用 ≥5 个真 / ≥5 个假整数恒等式，随机极性，由活跃的 `state` 值提供）。 | 调度器更大，更难化简。 _实测（§15）：运行期 +~5–10%，体积 +~1 KB。_ | 无（构造上保持行为等价）。 |
| `bogus_blocks` (`True`) | 通过永不触发的边注入不可达的伪造调度状态。 | 添加看似合理的死状态。 _实测（§15）：+~4 KB，且有真实运行期成本（cpu ≈+35%）——平铺调度需多跳过守卫。_ | 行为保持（不可达）。 |
| `bogus_clone_ratio` (`1.0`) | 伪造块中通过**克隆并变异真实块**来构建的比例（其余为合成的拟真体）。`0.0` = 全部合成。 | 取值 `1.0` 时伪造状态看起来像真实分支而非明显垃圾。 | 克隆需要真实流上存在真实块；若不存在则退回到合成。克隆内容仅流向不可达的伪造状态。 |
| `dedup` (`False`) | 合并字节完全相同的调度块（不动点迭代）。 | 调度器体积更小。 _实测（§15）：可忽略。_ | 跳过需要按块独立密钥（`needs_k`）的块，例如 attest/key-const 块。 |
| `state_delta` (`False`) | 相对转移：`state = T` 变为 `state += (T - k)`。 | 隐藏绝对目标状态值。 _实测（§15）：可忽略。_ | 无。 |
| `dispatch_tree` (`False`) | 将扁平的 `if state == k` 链替换为二叉搜索树调度（不含 `state == k` 叶节点）。 | 消除调度器中等值比较的特征签名。 _实测（§15）：运行期比平铺链更快（cpu ×2.5 vs 基线 ×4.5）。_ | 无。 |
| `junk_code` (`False`) | 在真实跳转边上插入**可达的**惰性垃圾块（死计算）。 | 增加运行时执行但无副作用的工作。 _实测（§15）：运行期 +~15%，体积 +~1 KB。_ | 行为保持；有少量运行时开销。 |
| `return_var` (`False`) | 将 `return x` 重写为 `_r = x; return _r`（裸 `return` 重写为 `_r = None`）。 | 规范化返回点。 _实测（§15）：可忽略。_ | 无。 |

---

## 3. 数据与常量混淆

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `obf_strings` (`True`) | 通过幂次/RSA 风格的编解码器（`pow(m,e,n)`，辅助函数 `_dec`）将 `str`/`bytes` 字面量编码为运行时解码表达式。 | 输出中不再有明文字符串/字节字面量；有一定的大小与运行时开销。 _实测（§15）：数值代码≈免费，字符串密集代码运行期≈×26（依赖数据类型）。_ | 当 `const_archive` 开启时被其取代。文档字符串**不会**被编码（保持明文 — 参见警告）。 |
| `obf_ints` (`False`) | 将整数常量编码为基于状态键的表达式（`enc - (state & mask)`，按块独立密钥）。 | 隐藏数值字面量。 _实测（§15）：运行期 +~10%，体积 +~0.6 KB。_ | 因会造成膨胀而默认不开启。跳过 `abs(n) <= 1` 的值。仅适用于急切路径。 |
| `const_archive` (`False`) | 将**所有** `int`/`float`/`str`/`bytes` 字面量汇聚到一个分层加密的数据包中，并通过 `_get(off,sz,key,cast)` 访问器读取。 | 以一个不透明数据包代替大量内联字面量；取代内联 `obf_strings`/`obf_ints` 编码。 _实测（§15）：数据体积最大（+~10 KB），但字符串解码比 `obf_strings` 便宜（str ×5.7 vs ×26）。_ | 固定数据包较大；访问器增加少量每次读取开销。跳过微小整数（`abs(v) <= 1`）及标记为不归档的节点。 |
| `hide_compares` (`False`) | 将用户代码中的 `expr == CONST` / `!= CONST`（整数，`|CONST| > 1`）改写为 `_h(expr) <op> <baked>`，其中 `_h` 是双射函数 `splitmix64(zigzag)`，`<baked>` 为构建时计算的 `_h(CONST)`。 | 常量不再以明文出现在比较位置，因此插桩差分分析只能读到 64 位摘要。纯整数运算 ⇒ **可移植**（TEXT + PYC，跨版本）。 _实测（§15）：除非有大量合格比较，否则近乎免费。_ | 仅作为提高门槛的手段：从摘要出发，小常量仍可暴力破解。配合 `body_cohash` 在 PYC 上使用时可完全封闭。不处理调度器自身的 `state == k` 比较（该选项在展平之前运行）。 |

---

## 4. 调用与名称隐藏

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `stack_calls` (`False`) | 通过隐藏的 `threading.local` 压栈/弹栈/调用栈来路由符合条件的内部函数调用参数，而非使用直接调用语法。 | 隐藏调用元数与参数连接关系。 _实测（§15）：运行期近乎免费，体积 +~2 KB。_ | 仅路由安全、可解析的调用（唯一的非方法定义，无复杂参数形式）。 |
| `hide_external_args` (`False`) | 同时通过隐藏栈路由外部/原生调用的位置参数。 | 将参数隐藏扩展到库/内置函数调用。 _实测（§15）：调用密集代码上较重（str ×8.9），体积 +~3 KB。_ | 当存在反 TOCTOU 机制时，在启动器上禁用（否则会破坏 oracle/审计闭包）。 |
| `split_calls` (`False`) | 将隐藏参数调用的压栈/弹栈/调用操作分散到 ≥2 个调度块中。 | 进一步消除调用点的特征签名。 _实测（§15）：成本与 `hide_external_args` 相同。_ | 需要 `stack_calls`/`hide_external_args` 开启才能生效。 |
| `slot_vars` (`False`) | 将安全的函数局部变量映射到新建的 `_slots` 列表的索引（`_slots[i]`）。 | 消除局部变量名称。 _实测（§15）：近乎免费。_ | 仅限可确定安全的局部变量（排除参数、捕获变量、`global`/`nonlocal`、推导式/with/except 目标）。 |
| `dict_indirect` (`False`) | 通过作用域内的 `_D[key]` 字典来路由内部函数（及类常量全局变量）的引用。 | 通过下标访问隐藏可调用对象身份。 _实测（§15）：可忽略。_ | 排除方法、导出名称及 `del` 目标名称。 |
| `name_vault` (`False`) | 通过模块级保险库（`_D[k] = getattr(builtins, name)` / `__import__(mod)`）路由被引用的内置函数与简单顶级导入，保险库本身由字符码 `__import__('builtins')` 引导启动。 | 内置/导入名称变为整数键查找；名称字符串随后由 `const_archive` 汇聚。 _实测（§15）：运行期 +~10–30%，体积 +~2 KB。_ | 排除 `super`（需要词法 `__class__` 单元格）、双下划线名称、被遮蔽的名称及装饰器位置的名称。仅当同时开启 `const_archive` 时名称字符串才不再以明文出现（该选项在之后运行）。 |
| `name_vault_attrs` (`False`) | 同时将属性读取 `obj.attr` → `getattr(obj, "attr")`（以及通过 `setattr`/`delattr` 进行的写入/删除）路由到保险库，汇聚属性名称字符串。 | 隐藏 `.attr` 接触面（例如 `sys.settrace`/`monitoring` 反调试属性名）。 _实测（§15）：≈与 `name_vault` 相同。_ | **需要 `name_vault`。** 仅限加载上下文读取及单目标写入/删除；装饰器位置的属性保持裸露。 |

---

## 5. 打包器与控制流派生密钥

打包器将混淆后的函数体包裹在一个加密数据包中，由启动器解密后 `exec` 执行。这部分仅适用于 `output` 为 `"text"`/`"pyc"` 的情形。

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `pack_body` (`False`) | 将混淆后的函数体包裹在压缩加密数据包中，由启动器在其自有全局作用域中重建并 `exec` 执行。 | 函数体不再可直接读取；启动器负责携带它。 _实测（§15）：构建 +~28 ms；一次性启动 +~10–20 ms；zlib 压缩后的数据包常比内联体更小。_ | 对 `output="ast"` 无效。函数体在加密前会先进行 zlib 压缩（自动）。 |
| `pack_format` (`"auto"`) | 函数体序列化方式：`"auto"`（`.py` → 源码 / `.pyc` → 字节码）、`"source"`、`"bytecode"`。 | `bytecode` 体积紧凑但锁定版本；`source` 可移植。 | `auto` 跟随 `output` 设置。 |
| `key_from_cff` (`False`) | 从启动器自身正确调度路径的折叠结果（`KDF(fold)`）派生解密密钥，而非使用存储的常量。 | 篡改展平后的控制流 ⇒ 密钥错误 ⇒ 乱码/诱饵。 _实测（§15）：相对 `pack_body` 可忽略。_ | 不开启时使用临时硬编码密钥（安全性低得多）。`attest` 必须开启此选项。 |
| `obf_imports` (`False`) | 通过 `__import__(''.join(map(chr,…)))` 路由启动器自身的导入（`sys`/`marshal`/`zlib`/`base64`）。 | 文本发行版中不再有可 grep/编辑的 `import` 语句。 _实测（§15）：可忽略。_ | 无。 |

---

## 6. 完整性与诱饵

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `integrity_selfcheck` (`False`) | 将内置函数身份检查（`type(sum/open/len/…) is builtin_type`）折叠到密钥选择器中。 | 内置函数被猴子补丁替换 ⇒ 密钥错误 ⇒ 诱饵。 _实测（§15）：可忽略。_ | 检查范围见 `builtin_checks`/`builtin_spot_count`。 |
| `cohash_integrity` (`False`) | 将某个未展平守卫函数的 `co_code` 的运行时哈希折叠到选择器中。 | 修补守卫的字节码 ⇒ 密钥错误 ⇒ 诱饵。 _实测（§15）：体积 +~2 KB，运行期可忽略。_ | **TEXT 上会锁定版本**（哈希与版本相关的字节码）—— 在不同 Python 版本上正常运行时会解码出诱饵。对 TEXT 发出警告；如需可移植性请使用 PYC（已通过魔数锁定版本）。 |
| `body_cohash` (`False`) | 函数体自我验证：每个 oracle 门控的转移在运行时重新折叠 `H = hash(guard.__code__.co_code)`；构建时将 `H_build` 烘焙到修正值中，使得正常路径相互抵消，而任何函数体重新编译/插桩都会翻转 `H` → 诱饵。 | 将完整性验证从启动器扩展到函数体。 _实测（§15）：在 `attest` 之上近乎零成本（+~0.3 KB）。_ | **需要 `attest=True` 且 `output="pyc"`**（否则显式报错 `ValueError`）—— TEXT 函数体会被最终用户重新编译，其 `co_code` 将与烘焙的哈希不匹配。 |
| `pack_decoy` (`False`) | 在被篡改/走错路径时，无分支地解密并运行一个**诱饵**函数体，而非直接失败。真实体与诱饵共享一个密文；选择通过 `dict.get` 加算术实现，不存在可修补的布尔值。真实密钥仅以 `K_real ^ S_correct` 的形式存储。 | 检测变为蜜罐：攻击者到达一个可信的诱饵。 _实测（§15）：构建 +~0.6 KB（诱饵也会被混淆）；运行期可忽略。_ | 若提供了 `decoy_src` 则使用该源码，否则使用内置哨兵诱饵。嵌入的诱饵经过同一流水线混淆（参见 `decoy_obf_overrides`）。 |

---

## 7. 检测（反调试信号）

每个检测器贡献一个项：在干净的进程中该项为 `0`，触发时为 `> 0`。将信号折叠到密钥中需要开启 `key_binds_env`；不开启时，信号仍会被计算并暴露给 `handler_src`，但不影响密钥。

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `key_binds_env` (`False`) | 允许已启用的检测信号折叠到密钥选择器中（任意触发 ⇒ 密钥错误 ⇒ 诱饵）。 | 将检测转化为密钥绑定。 _实测（§15）：可忽略。_ | 默认关闭以避免假阳性。构建假定在干净环境下运行（聚合值 `== 0`）。 |
| `detect_trace` (`False`) | 将 `sys.gettrace()` / `getprofile()` 的活动折叠到检测聚合中。 | 在加载时捕获调试器 / 基于 `settrace` 的追踪器 / 覆盖率工具。 _实测（§15）：可忽略。_ | 在覆盖率/性能分析工具下可能产生假阳性。 |
| `detect_tools` (`False`) | 将 `sys.modules` 指纹（pydevd/debugpy/coverage）折叠到聚合中。 | 捕获常见调试/覆盖率工具。 _实测（§15）：可忽略。_ | 基于模块名称进行检测。 |
| `detect_env` (`False`) | 将"breakpointhook 被替换" / 解释器检查模式（`-i`/`PYTHONINSPECT`）折叠到聚合中。 | 捕获调试器设置的钩子及检查模式。 _实测（§15）：可忽略。_ | — |
| `detect_stack` (`False`) | **仅限入口点。** 将"入口经由外部 `exec`/`import`/`runpy`/`-m` 而非 `python file` 到达"折叠到聚合中。 | 捕获通过 exec/import 脚本来提取内容的工具，即使它们伪造了 `__name__ == "__main__"`。 _实测（§15）：可忽略。_ | **假阳性风险高且仅限入口点** —— 不纳入任何预设。将 `import <module>` 设计为返回诱饵（正常入口为 `python <module>`）。自动适应 `compress_output` 包装的额外栈帧。 |
| `builtin_checks` (`("compile","exec","pow","sum","open","len")`) | 在完整性折叠中获得相对身份项的内置函数列表。 | 可配置的反猴子补丁覆盖面。 | `compile`/`exec` 还通过其有效（全局或内置）绑定进行额外检查，以捕获全局遮蔽。 |
| `builtin_spot_count` (`3`) | 每次构建时，额外随机抽查此数量的内置函数，使用绝对"是否为 Python 定义的函数？"（`__code__`）项。 | 捕获**均匀**替换每个内置函数的情形（纯相对检查的盲区）。 | 上限为 `len(builtin_checks)`。 |

---

## 8. 证明（cff ↔ python oracle）

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `attest` (`False`) | 启动器向函数体全局作用域安装一个 oracle `O(s) = mix(s, S_correct, MAGIC)`；调度器中部分跳转变为 `state = O(state) ^ CORRECTION`，使下一个状态同时依赖运行时状态、启动器密钥和魔数。在没有 oracle 的情况下转储函数体会导致路径偏离 —— 破解离线转储重放。 | 对提取并重放函数体数据包的攻击具有强防御效果。 _实测（§15）：成本最高的标志——运行期 ≈2×、构建 ≈7×。_ | **需要 `pack_body=True`、`key_from_cff=True` 且 `output` 为 `"text"`/`"pyc"`**（否则显式报错 `ValueError` —— 是打包器负责安装 oracle 并修补修正值）。 |
| `attest_density` (`0.3`) | 通过 oracle 门控的调度器跳转比例（确定性目标，保证下界）。 | 值越高 = 门控越多 = 防篡改覆盖越强，输出越大。 _实测（§15）：运行期随密度上升——cpu 从 0.1 的 ×11.6 到 1.0 的 ×30。_ | 需要足够多的块；参见 `attest_inflate`。 |
| `attest_inflate` (`True`) | 通过注入死克隆块来扩充小/低复杂度的处理单元，使密度在小函数上也能生效。 | 让密度在小函数上也能取得效果。 | 仅在 `attest` 激活时有效；克隆块永远不会被执行。 |
| `attest_target_blocks` (`10`) | 当 `attest_inflate` 开启时，每个展平单元最多扩充到此数量的调度块。 | 控制扩充预算。 | — |
| `attest_runtime_bind` (`False`) | 安装的 oracle 的密钥额外折叠一个**运行时**信号（`gettrace`/`getprofile`/审计毒化/`pow` 重检），在每次门控跳转时重新评估。 | 在**任意时刻**（即使在函数体执行中途）附加追踪器都会使下一次门控转移偏离正确路径。 _实测（§15）：比单独 `attest` 略多运行期（cpu ×19.5）。_ | **需要 `attest`。** 假阳性风险高（覆盖率/性能分析工具）；默认关闭，不纳入任何预设。干净环境 ⇒ 信号为 `0` ⇒ 正常路径字节完全一致。 |

---

## 9. 反 TOCTOU（加载时 → 运行时间隙）

所有选项默认**关闭**且**不纳入任何预设** —— 在覆盖率/性能分析工具下可能产生假阳性。

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `detect_audit` (`False`) | 安装一个 `sys.addaudithook` 绊线，在发生任何 `sys.settrace`/`setprofile` 事件时设置持久毒化单元格。 | 捕获在一次性引导检查**之后**附加的追踪器；在 `key_binds_env` 下折叠到聚合中，并被 `attest_runtime_bind` 及中和器读取。 _实测（§15）：可忽略。_ | 假阳性风险高。 |
| `anti_trace_neuter` (`False`) | 在 `exec` 函数体之前，中和调试设置 API（`sys`/`threading` 的 settrace/setprofile、`sys.addaudithook`、3.12+ 上的 `sys.monitoring`）。`settrace(None)` 仍然放行；非 None 的追踪器安装请求被黑洞吞噬（默认），并毒化单元格。 | 主动阻断追踪器安装。 _实测（§15）：启动器体积约翻倍（+~7.6 KB），构建 +~22 ms；运行期不变。_ | 假阳性风险高。 |
| `anti_trace_neuter_honeypot` (`False`) | 中和器的响应模式：`True` = 在追踪器安装尝试时运行诱饵后 `SystemExit`；`False`（默认）= 静默黑洞 + 毒化。 | 较明显的响应 vs 较隐蔽的响应。 _实测（§15）：≈与中和器相同。_ | 需要 `anti_trace_neuter`。 |

---

## 10. 输出包装与分发

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `compress_output` (`False`) | 最终分发包装：对整个输出载荷进行 zlib + 滚动 XOR 处理，由一个微型引导程序重新 `exec`（TEXT → b85 源码包装；PYC → 马歇尔化代码包装）。 | 缩小分发文件体积，并增加一个静态提取的速度障碍，引诱 exec 钩取进入完整性蜜罐。 _实测（§15）：体积 ≈−36%；运行期/启动不变。_ | 仅适用于 `output` 为 `"text"`/`"pyc"`。`detect_stack` 会自动适应新增的包装栈帧。 |
| `compress_rounds` (`1`) | `compress_output` 的递归深度：将载荷包装 N 层（载荷被解压后 `exec` N 次）。 | `N > 1` 不会进一步缩小体积，但迫使提取工具剥离 N 层；每层增加一个 `exec` 栈帧（`detect_stack` 走 `rounds + 1` 帧）。 _实测（§15）：每层 +~0.3 KB，运行期不变。_ | 需要 `compress_output`。 |
| `require_min_python` (`False`) | 在最外层包装中生成一段明文守卫，若运行时版本低于 `MIN_SUPPORTED_PYTHON`（`(3, 11)`）则以简洁的"requires Python X.Y+"消息 `SystemExit`。 | 在解释器版本过低时给出友好提示，而非产生晦涩错误。 _实测（§15）：可忽略。_ | **仅限 TEXT** —— 对 PYC/AST 无效且发出警告（`.pyc` 已通过魔数锁定版本）。消息中刻意不提及工具名称。 |

---

## 11. 预设

| Option (default) | Effect |
|---|---|
| `protect_level` (`"off"`) | 对各独立保护标志的便捷打包。`"off"` = 使用各独立标志（无预设）。`"light"` = `pack_body + key_from_cff + integrity_selfcheck + pack_decoy + obf_imports`（静态保护 + 诱饵，仍可调试）。`"full"` = `light` + `detect_trace + detect_tools + detect_env + key_binds_env`（增加反追踪蜜罐）。非 `off` 预设会**覆盖设置**相应标志（忽略单独设置的值）。`detect_stack` 及反 TOCTOU 标志不纳入任何预设。 _实测（§15）：light/full ≈ `pack_body` 基线 + ~10 ms 启动；打包体比未压缩 defaults 更小。_ |

---

## 12. 仅限模块的选项（`ModuleObfOptions`）

| Option (default) | Effect | Impact | Limitations |
|---|---|---|---|
| `decoy_src` (`None`) | `pack_decoy` 使用的诱饵程序源码。 | 提供构建时精心编写的真实诱饵。 | `None` ⇒ 使用内置哨兵诱饵。 |
| `decoy_obf_overrides` (`None`) | 用于嵌入诱饵混淆的每标志 CFF 覆盖值（例如：去掉不透明谓词 / 字符串混淆，使触发的诱饵易于阅读）。 | 独立于函数体调整诱饵的强度。 | 在函数体标志基础上叠加应用。`attest`/`attest_runtime_bind`/`body_cohash`/`cohash_integrity`/pack/compress 对诱饵**始终强制关闭**（诱饵会在选择它的调试器下运行）。 |
| `handler_src` (`None`) | 内联一个构建时编写的蜜罐处理器，通过 `M.TRACE/TOOLS/ENV/STACK` 读取检测信号并可设置 `M.POISON`。 | 自定义策略，并为假阳性风险高、不应触碰密钥的信号提供安全出口。 | `POISON` 像检测聚合一样折叠到选择器中；构建假定 `POISON == 0`。 |
| `exports` (`[]`) | 视为模块公共接口的名称列表。 | 保持对外部可调用/可见。 | — |
| `exports_from_all` (`True`) | 将 `__all__` 视为导出列表。 | 尊重模块声明的公共接口。 | — |
| `emit_pyi` (`False`) | 生成 `.pyi` 存根接口文件。 | 对类型检查器可见的接口。 | — |
| `single_file_interface` (`False`) | 单文件接口模式。 | — | — |

---

## 12b. `obf_project` — 多模块项目混淆

```python
from pyobfuscator import obf_project, ModuleObfOptions

manifest = obf_project(
    root="src/myapp",
    out="dist/myapp",
    entry="main.py",
    protect=["app/secret.py", "app/logic/*.py"],
    options=ModuleObfOptions(
        output="pyc", seed=42,
        pack_body=True, key_from_cff=True,
        attest=True, pack_decoy=True,
    ),
)
# manifest == {"main.py": "entry", "app/secret.py": "protect",
#              "app/__init__.py": "plaintext", ...}
```

`obf_project` 对整个 Python 源代码树进行混淆。它将目录树镜像到 `out`，对选定的文件进行混淆，其余文件逐字复制。返回一个 `{相对路径 → 角色}` 清单，其中角色为 `"entry"`、`"protect"` 或 `"plaintext"`。

### 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `root` | — | 源代码树根目录。 |
| `out` | — | 输出目录。源代码树布局将被镜像到此处。 |
| `entry` | — | 入口模块的相对路径（如 `"main.py"`）。必须存在于 `root` 下，否则大声报错。 |
| `protect` | `None` | 用于选择待混淆文件的相对路径和/或 `fnmatch` 通配符模式列表。即使某个模式匹配了入口文件，入口也不会被纳入此集合。每个模式必须至少匹配一个文件（否则大声报错）。`None` 或 `[]` 表示无卫星文件。 |
| `options` | `ModuleObfOptions()` | 一个 `ModuleObfOptions` 实例（与 `obf_module` 使用的是同一个选项对象）。同一个 `seed` 在所有文件间共享，这使得选择器 `s_correct = f(seed)` 能够在各处保持一致，而无需依赖构建顺序。 |
| `import_hook` | `False` | 为 `True` 时，卫星 blob 被嵌入到入口内部的注册表中，入口会安装一个 `sys.meta_path` 查找器，在 `import` 时即时解密卫星。此模式下，卫星不会生成单独的存根 `.py`/`.pyc` 文件；明文包文件（如 `app/__init__.py`）仍会正常生成。需要共享运行时模式（否则抛出 `ValueError`）。 |
| `shared_oracle_decouple` | `False` | Oracle 绑定模式。`False`（默认，**beta**）：共享 `dec` 函数封闭入口的运行时选择器——篡改入口调度器会导致每个卫星解密出诱饵。`True`（**alpha**）：`dec` 封闭构建时的常量选择器，卫星独立于入口的运行时完整性（适用于增量构建流水线）。两种模式下卫星 blob 的字节内容完全相同。 |

### 两种运行模式

**共享运行时模式**在以下条件同时满足时激活：`options` 启用了完整的证明栈（`attest=True` + `pack_body=True` + `key_from_cff=True` + `output` 为 `"text"`/`"pyc"`），且存在至少一个受保护文件。在此模式下：

- 入口以一个额外步骤构建，该步骤将一个共享 `dec` 函数（解密 + 解压 + exec）和证明 oracle 发布到 `builtins`。
- 每个受保护模块以小型**存根** + 加密 blob 的形式分发。存根调用已发布的 `dec`，`dec` 解密出真实或诱饵体，将 oracle 注入卫星自身的模块全局作用域，然后在其中 `exec`。普通的 `import app.secret`（或 `from app.secret import x`）透明工作，包括来自明文模块的反向导入。
- 由于 `s_correct = f(seed)` 仅依赖种子（以及 `builtin_checks` 选项），而不依赖任何文件的源码，各文件可以**按任意顺序独立构建**。以相同 seed 重新构建单个卫星并将其替换到现有输出中即可——不变的入口能正确运行它。

**自包含回退模式**在证明栈未启用（或无受保护文件）时激活。每个受保护和入口文件均作为独立的自包含单模块启动器构建，无共享运行时。受保护文件无需入口即可自行解密。

### 入口绑定的大声报错

在**共享运行时模式**下，若在入口尚未将共享 `dec` 发布到 `builtins` 的情况下导入卫星，将在运行时大声报错——卫星存根对缺失 `dec` 的调用会抛出 `AttributeError`。卫星不支持独立运行或独立导入。

### PYC 输出

当 `options.output == "pyc"` 时，混淆后的文件以无源码 `.pyc` 形式输出：`main.py` → `main.pyc`（通过 `python main.pyc` 运行）；`app/secret.py` → `app/secret.pyc`（通过 `import app.secret` 导入）。明文文件始终保持 `.py` 名称。

### 适用范围与已知限制

支持：常规包（`app/__init__.py` 若在 `protect` 中则被混淆，否则复制为明文）、来自明文模块的反向导入，以及循环导入（遵循标准 Python 语义）。

不支持：命名空间包（无 `__init__.py`）、C 扩展（`.pyd`/`.so`），以及通过 `python -m <卫星>` 直接运行卫星。

可运行的演示位于 `sample/project_test/`（通过 `build_project.py` 构建）；单文件演示位于 `sample/single_file/`。

---

## 13. 显式报错前置条件汇总

API 会预先拒绝以下组合（而非生成一个在正常路径上就会崩溃的启动器）：

| 若设置了… | 还必须设置… | 否则 |
|---|---|---|
| 使用了 `precompile_arg("KEY")`（单参数） | `"KEY"` 存在于 `precompile_args` 中 | `ValueError` |
| 使用了 `precompile(expr)` | `expr` 在模块作用域可求值（非函数参数） | `ValueError`（子进程 eval 错误） |
| `attest=True` | `pack_body=True` **且** `key_from_cff=True` | `ValueError` |
| `attest=True` | `output` 属于 `{"text", "pyc"}` | `ValueError` |
| `body_cohash=True` | `attest=True` | `ValueError` |
| `body_cohash=True` | `output="pyc"` | `ValueError` |
| `attest_runtime_bind=True` | `attest=True` | （不开启则无效果） |
| `name_vault_attrs=True` | `name_vault=True` | （不开启则无效果） |
| `import_hook=True`（在 `obf_project` 中） | 共享运行时模式（`attest` + `pack_body` + `key_from_cff` + text/pyc + ≥1 个受保护文件） | `ValueError` |

警告（非错误）：

- `cohash_integrity=True` 且 `output="text"` —— 锁定 TEXT 启动器的版本（发出警告）。
- `require_min_python=True` 且 `output` 为 `"pyc"`/`"ast"` —— 被忽略（发出警告）。
- 任何将保留在输出中的明文文档字符串 —— 发出警告，以便移除敏感内容。

---

## 14. 可移植性速查表

| 目标 | 使用 | 避免 |
|---|---|---|
| 跨版本源码发行 | `output="text"` + 可移植标志（`hide_compares`、`attest`、`pack_decoy`、检测类选项） | `cohash_integrity`、`body_cohash`（会锁定版本） |
| 版本锁定紧凑二进制 | `output="pyc"` + `body_cohash` + `cohash_integrity` | —（`.pyc` 已通过魔数锁定） |
| 可导入/可直接运行的单文件 | `output="pyc"` 命名为 `<module>.pyc`（参见 `sourceless_pyc_name`） | 若需要 `import <module>` 正常工作则避免 `detect_stack`（该选项设计上会在 import 时返回诱饵） |

---

## 15. 实测性能

下列数字由 [`bench/benchmark.py`](../bench/benchmark.py) 生成，且**依赖具体机器**——请在你的目标机器上用以下命令重新生成：

```
.venv/Scripts/python bench/benchmark.py            # 完整矩阵
.venv/Scripts/python bench/benchmark.py --quick     # 较小子集（开发用）
```

本次运行环境：Python 3.14.4、Windows 11 (x86-64)、`seed=20260618`；构建取 3 次中位数，运行取
4 次可杀子进程的中位数。

**测量的指标**（每个配置，均与未混淆基线对比）：

- **build** — `obf_module()` 的墙钟时间。
- **size** — 产物字节数。
- **runtime (×)** — 产物自身的热循环（在子进程中运行）相对于未混淆源码运行时间的倍数。
- **startup** — `子进程墙钟 − 函数体运行 − 空解释器启动`：启动器一次性解密 + `exec`（+ 解压）的成本。

使用两个 workload，因为运行期开销**强依赖数据类型**：`cpu`（整数 / 分支 / 循环密集，基线
68.8 ms）与 `str`（字符串 / 字节密集，基线 48.7 ms）。全部 106 个配置都产生了行为一致的结果
（checksum 相符）——这是对等价性门控的一次运行期佐证。

**口径说明。** 运行间噪声约 ±10%——不要过度解读 10% 以内的差异。`startup` 是派生估计值（三个接近
解释器启动量级的时间相减），仅作指示（±数 ms），并非精确值。

### 15.1 控制流平坦化（CFF）层

`build`/`size` 为 `cpu` workload；`runtime` 同时给出两者。以纯展平（所有 CFF 标志关闭）为基线的
边际成本。

| Config | build (ms) | size (B) | cpu runtime (×) | str runtime (×) |
|---|---|---|---|---|
| baseline (plain flatten) | 10 | 6248 | 4.5 | 2.5 |
| defaults (`obf_strings`+`shuffle_states`+`opaque_predicates`+`bogus_blocks`) | 25 | 11978 | 9.0 | 28.2 |
| `obf_strings` | 13 | 6780 | 4.5 | 25.6 |
| `obf_ints` | 13 | 6859 | 5.0 | 2.7 |
| `shuffle_states` | 11 | 6674 | 3.4 | 3.3 |
| `opaque_predicates` | 13 | 7289 | 4.8 | 2.6 |
| `bogus_blocks` | 18 | 10170 | 6.1 | 4.0 |
| `slot_vars` | 13 | 6465 | 4.9 | 2.7 |
| `stack_calls` | 15 | 8612 | 4.5 | 2.5 |
| `hide_external_args` | 16 | 9386 | 4.5 | 8.9 |
| `split_calls` (+`hide_external_args`) | 16 | 9386 | 4.5 | 8.9 |
| `return_var` | 10 | 6310 | 4.5 | 2.5 |
| `dedup` | 11 | 6248 | 4.5 | 2.5 |
| `state_delta` | 11 | 6268 | 4.6 | 2.7 |
| `dispatch_tree` | 10 | 6891 | 2.5 | 2.1 |
| `junk_code` | 12 | 7502 | 5.1 | 2.8 |
| `dict_indirect` | 12 | 6338 | 4.5 | 2.5 |
| `const_archive` | 29 | 16711 | 9.2 | 5.7 |
| `name_vault` | 15 | 8024 | 4.9 | 3.3 |
| `name_vault_attrs` (+`name_vault`) | 16 | 8072 | 5.0 | 3.3 |
| `hide_compares` | 12 | 6907 | 5.3 | 2.5 |

亮点：`dispatch_tree` 比平铺链**更快**（每步比较更少）；`obf_strings` 在数值代码上近乎免费，但在
字符串密集代码上 ≈×26；`const_archive` 解码字符串比 `obf_strings` 便宜（×5.7 vs ×26），但数据体积
最大（+10 KB）；`bogus_blocks` 虽不可达却增加真实运行期，因为平铺调度需跳过更多守卫
（`dispatch_tree` 可同时消除该特征与该成本）。

### 15.2 保护层

以 `pack_body`+`key_from_cff` 为基线的边际成本（`cpu` workload）。打包后的函数体以混淆默认值的
速度运行；只有 `attest` 改变函数体运行期。打包增加一次性启动 ≈10–20 ms。

| Config | build (ms) | size (B) | cpu runtime (×) |
|---|---|---|---|
| base (`pack_body`+`key_from_cff`) | 39 | 7722 | 9.0 |
| `integrity_selfcheck` | 43 | 8303 | 8.9 |
| `cohash_integrity` (text: version-locks) | 43 | 9822 | 8.9 |
| `pack_decoy` | 41 | 8304 | 9.0 |
| `obf_imports` | 41 | 7803 | 9.0 |
| `detect_trace` (+`key_binds_env`) | 40 | 7957 | 9.0 |
| `detect_tools` (+`key_binds_env`) | 41 | 8005 | 9.0 |
| `detect_env` (+`key_binds_env`) | 41 | 7996 | 9.0 |
| `detect_stack` (+`key_binds_env`) | 40 | 7919 | 9.0 |
| `detect_audit` | 42 | 8047 | 9.0 |
| `anti_trace_neuter` | 61 | 15320 | 9.0 |
| `anti_trace_neuter` + `honeypot` | 62 | 15810 | 9.0 |
| `attest` (density 0.3) | 74 | 10825 | 17.1 |
| `attest` + `attest_runtime_bind` | 79 | 11726 | 19.5 |
| `compress_output` | 39 | 4916 | 9.0 |
| `compress_output` rounds=2 | 40 | 5207 | 9.0 |
| `require_min_python` | 39 | 7896 | 9.0 |
| `body_cohash` (pyc, over `attest`) | 75 | 11814 | 18.4 |

亮点：`attest` 是成本最高的标志——运行期 ≈2×、构建 ≈7×；`attest_runtime_bind` 再略增。
`anti_trace_neuter` 使启动器体积约翻倍。`compress_output` 将产物**缩小** ≈36% 且运行期不变。
`body_cohash` 在 `attest` 之上近乎免费（pyc `attest` 基线实测 ×18.2）。其余（完整性 / 检测 / 诱饵 /
导入）均在 build/size 噪声范围内。

### 15.3 预设（`protect_level`）

累计，`cpu` workload，输出 `text`。

| protect_level | build (ms) | size (B) | startup (ms) | runtime (×) |
|---|---|---|---|---|
| off | 25 | 11978 | ~4 | 9.0 |
| light | 46 | 8928 | ~10 | 9.0 |
| full | 48 | 9564 | ~11 | 9.0 |

`light`/`full` 比 `off` 更小，因为打包体经 zlib 压缩，而 `off` 内联携带混淆默认值。

### 15.4 旋钮扫描

`cpu` workload。

| Knob | value | size (B) | runtime (×) |
|---|---|---|---|
| `attest_density` | 0.1 | 10740 | 11.6 |
| `attest_density` | 0.3 | 10825 | 17.3 |
| `attest_density` | 0.6 | 10703 | 20.2 |
| `attest_density` | 1.0 | 10856 | 30.3 |
| `compress_rounds` | 1 | 4916 | 9.0 |
| `compress_rounds` | 2 | 5207 | 9.0 |
| `compress_rounds` | 3 | 5498 | 9.0 |
| `min_blocks` | 2 | 11978 | 8.9 |
| `min_blocks` | 4 | 9928 | 8.9 |
| `min_blocks` | 8 | 8134 | 8.9 |

`attest_density` 以运行期换取防篡改覆盖率（运行期的主导旋钮）。`compress_rounds` 每多剥一层增加
≈0.3 KB 且运行期不变。提高 `min_blocks` 通过让更多小函数不展平来缩小产物。
