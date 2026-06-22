# pyobfuscator — 架构与文件索引

本文档是包的导航地图，面向扩展或维护该项目的开发者。内容涵盖顶层数据流、Pass 流水线、`protect → cff` 依赖规则，以及 `src/pyobfuscator/` 下**每个**模块的职责、对外接口与交互关系。

该包分为两层：

- **`cff/`** — 控制流平坦化引擎。将每个函数 / 方法 / 模块体转换为 `while True` 状态机调度器，并施加加固变换。
- **`protect/`** — Python 层保护 / 打包器。将已混淆的模块包裹在一个启动器中，启动器以压缩 + 加密的 blob 形式携带模块体，并在运行时重建。

**依赖规则：** `protect` 可以从 `cff` 导入；**`cff` 绝不能导入 `protect`**（特别注意 `cff/attest.py`，它与打包器共享 oracle `mix()`，但保持自包含）。

---

## 顶层数据流

`obf_func(src, options)` （[`__init__.py`](../src/pyobfuscator/__init__.py)）：

```
src → _FUNC_PIPELINE.run → emit(tree, options)
```

`obf_module(src, options)`：

```
src → (大声报错的前置条件检查)
    → _MODULE_PIPELINE.run        # Pass 流水线
    → wrap_module                 # 平坦化模块体
    → pack_module                 # （若 pack_body 且输出 text/pyc）启动器 + 诱饵 + 证明
    → _insert_version_guard       # （若 require_min_python，未压缩文本）
    → emit                        # 最终化名称并渲染为 text / pyc / ast
    → outer_compress              # （若 compress_output）zlib + 滚动 XOR + b85 自举
```

诱饵（当启用 `pack_decoy`）会经过**相同**的流水线（`_obfuscate_decoy`）进行混淆，因此解密后的诱饵在结构上与真实体无法区分。

`obf_project(*, root, out, entry, protect, options, import_hook, shared_oracle_decouple)`：

```
classify_files(root, entry, protect)   # → {相对路径 → Role}
    ↓ 是否启用共享运行时模式？（attest + pack_body + key_from_cff + text/pyc + ≥1 个受保护文件）
    是 → project_s_correct(options)   # 一个种子派生的选择器，被所有文件共享
          对每个 PROTECT 文件：
              _MODULE_PIPELINE.run → wrap_module
              build_satellite(tree, …) # 存根 + 加密 blob（s_correct = f(seed)，无构建顺序依赖）
              → 将存根输出到 <rel>.pyc  （或注册到入口的 import-hook 注册表中）
          obf_module(entry_src, …, publish_runtime=True,
                     shared_oracle_decouple=…, runtime_registry=…)
                       # 入口启动器额外将共享 dec 函数 + oracle 发布到 builtins
    否 → obf_module(每个受保护/入口文件)   # 独立单模块自包含回退
    对每个 PLAINTEXT 文件：shutil.copyfile 逐字复制
```

---

## Pass 流水线

`_FUNC_PIPELINE` 和 `_MODULE_PIPELINE`（顺序相同，定义于 `__init__.py`）按以下顺序运行各 Pass；每个 Pass 在变换之前都会通过 `gate.py` 强制执行默认拒绝节点白名单：

1. **`LocalCallPass`** — 处理 `@local_call`（内联/重命名被标记的辅助函数，去除标记导入）。
2. **`DictIndirectPass`** — 将内部函数引用通过每作用域的 `_D[key]` 字典（`dict_indirect`）进行路由。
3. **`NormalizePass`** — 将 `match` 脱糖为 if 链；可选的 `return_var` 改写（结构模式大声报错）。
4. **`CmpHidePass`** — 用双射摘要（`hide_compares`）隐藏整数 `==`/`!=` 常量。
5. **`LocalRenamePass`** — 将用户参数 / 局部变量 / 推导式目标重命名为新鲜名称（始终开启）。
6. **`StackCallPass`**（主阶段）— 将符合条件的调用参数通过隐藏的 `threading.local` 栈路由（`stack_calls`/`hide_external_args`）。
7. **`SlotVarPass`** — 将安全的局部变量映射到 `_slots[i]`（`slot_vars`）。
8. **`NameVaultPass`** — 将内置名称 + 简单导入通过每模块的 vault 路由（`name_vault`/`name_vault_attrs`）。
9. **`ArchivePass`** — 将所有字面量汇入一个加密 blob + `_get` 访问器（`const_archive`）。
10. **`DataObfPass`** — 对 `str`/`bytes` 字面量使用 pow/RSA 风格的编解码器（`obf_strings`）。
11. **`StackCallPass`**（`phase="post_vault"`）— 第二轮、针对性的参数隐藏 Pass，仅覆盖归档 `_get(...)` 访问器的调用点。
12. **`FlattenPass`** — 通过 `cfg.flatten_function` 对每个函数进行控制流平坦化，并穿透所有特性 RNG / 标志。

流水线结束后，`obf_module` 依次运行 `wrap_module`（平坦化模块体），然后（在 text/pyc 且启用 `pack_body` 时）运行 `pack_module`，最后运行 `emit`。

---

## 根包

### `__init__.py`
- **职责：** 公共 API 与编排。定义流水线，串接 `pipeline → wrap_module → pack_module → emit → outer_compress`，并包含大声报错的前置条件检查。
- **对外接口：** `obf_func`、`obf_module`、`obf_project`（入口点）；重导出 `ObfOptions`/`ModuleObfOptions`/`OutputFormat`/`UnsupportedPolicy`、`local_call`、分析 / 可视化函数；`cache_tag()`、`sourceless_pyc_name(module, *, tagged=False)`、`MIN_SUPPORTED_PYTHON`；内部的 `_FUNC_PIPELINE`/`_MODULE_PIPELINE`、`_obfuscate_decoy`、`_warn_docstrings`、`_warn_version_lock`、`_version_guard_src`、`_insert_version_guard`。
- **交互：** 导入每个 Pass；前置条件检查守护 `attest` / `body_cohash`；从 `protect.project` 重导出 `obf_project`。

### `options.py`
- **职责：** 所有配置以 dataclass 形式表达；是标志与默认值的单一真相来源。
- **对外接口：** `ObfOptions`、`ModuleObfOptions`、`OutputFormat`、`UnsupportedPolicy`、`_PROTECT_PRESETS`、`_apply_protect_level`（在 `__post_init__` 中展开 `protect_level`）。各标志的参考说明请见 [`OPTIONS.chs.md`](OPTIONS.chs.md)。
- **交互：** 在 `cff` 和 `protect` 中均被广泛读取。

### `packer.py`
- **职责：** 向后兼容的垫片 — 保护层已迁移至 `protect/`；此模块保持历史 `pyobfuscator.packer` 导入接口可用。
- **对外接口：** 从 `protect` 重导出 `pack_module` 和加密原语（`_ks_xor`、`_kdf`、`_fold`、`_MASK`、`_TEMP_KEY`）。

---

## `cff/` — 控制流平坦化引擎

### `cff/cfg.py`
- **职责：** 平坦化器。将结构化语句降级为基本块，渲染为 `while True` 调度器，然后原地应用完整的加固套件。
- **对外接口：** `Block` + 终止符 dataclass（`Goto`、`CondGoto`、`Ret`、`RaiseTerm`、`HandlerDispatch`、`SubExit`、`PopK`）；`Lowerer`（语句 → 基本块）；`desugar_with`；`build_blocks`；入口点 **`flatten_function`** 和 **`flatten_module_body`**；`_render`（基本块 → 调度器，附加 `_pyobf_scopemap`）；以及渲染后变换：`harden_states`、`dedup_blocks`、`key_consts`、`inject_attest`、`inflate_attest_blocks`、`inject_bogus`、`state_delta_transform`、`inject_opaque`、`dispatch_tree_transform`、`inject_junk_blocks`、`split_blocks`。渲染后顺序：`_render → dedup → harden → key_consts → inject_attest → inject_bogus → state_delta → inject_opaque → dispatch_tree`。
- **交互：** 使用 `names.Namer`、`diagnostics`；在 `inject_attest` 内部延迟使用 `attest`。由 `module_wrap` 和 `FlattenPass` 调用。

### `cff/module_wrap.py`
- **职责：** 将模块级代码体平坦化为模块调度器，保持文档字符串和 `from __future__` 导入在最前面；协调模块级证明 + cohash 定义的生成。
- **对外接口：** **`wrap_module(tree, options)`**；前导谓词 `_is_docstring`/`_is_future`。
- **交互：** 调用 `cfg.flatten_module_body`；在树上记录证明元数据；不导入 `protect`。

### `cff/attest.py`
- **职责：** 构建时与运行时的证明原语：oracle 哈希、种子派生名称 / 常量、oracle 门控跳转 AST 工厂、诱饵 oracle 回退，以及代码体自 cohash 机制。
- **对外接口：** `mix(s,k,m)`（oracle；也被 `protect/core.py` 导入）、`oracle_name(seed)`、`MAGIC(seed)`、`ATTEST_MIN_GATES`、`name_to_charcode_expr`、`make_setdefault_binding`、`make_oracle_goto_absolute`/`make_oracle_goto_relative`，以及 cohash 辅助函数：`cohash_names`、`cohash_build_hash`、`make_cohash_guard_def`、`make_cohash_hashfn_def`、`make_cohash_binding`。
- **交互：** 被 `cfg.inject_attest`、`module_wrap` 和 `protect/core.py` 导入。**绝不能导入 `protect`。**

### `cff/lambdalift.py`
- **职责：** 将所有可提升的 `ast.Lambda`（包括由 attest / 反追踪阶段生成的）替换为具名 `def`，消除 lambda 特征。
- **对外接口：** **`lift_lambdas(tree, namer)`**（不动点，闭包安全）；辅助函数 `_lift_one`、`_do_lift`、`_parent_map`、`_in_comprehension`、`_enclosing_stmt`。
- **交互：** 运行较晚（在 `emit` 中以及 `core` 中代码体序列化之前）；对每个被提升的 def 调用 `localrename.rename_simple_helper_locals`。

### `cff/rename.py`
- **职责：** 最终的确定性重命名：将每个单调临时名称（`_pyobf_g<n>`）替换为种子随机的统一格式 `_pyobf_<hex>`，对相同输入 + 种子产生字节完全相同的输出。
- **对外接口：** **`finalize_names(tree, seed, *, out_map=None, ns_salt=0)`**；内部类 `_Rewriter`。
- **交互：** 读取 `names._GEN_ISSUED`；`ns_salt` 使代码体 / 启动器 / 诱饵的命名空间相互隔离；从不触碰双下划线证明名称。

### `cff/names.py`
- **职责：** 进程全局、无碰撞的名称工厂 + 名称收集器；是已生成临时名称及其来源（用于 sourcemap）的单一真相来源。
- **对外接口：** **`Namer`**（`fresh(hint, *, orig, scope, kind)`）、`collect_names(node)`、`name_meta`，以及进程全局的 `_GEN_COUNTER`/`_GEN_ISSUED`/`_GEN_META`。
- **交互：** 几乎所有 `cff` 模块都导入它；`_GEN_ISSUED` 是跨 Pass 的唯一性契约。

### `cff/emit.py`
- **职责：** 最终输出阶段 — lambda 提升 + 最终化名称，可选 sourcemap，然后渲染为 AST / 文本 / `.pyc`。
- **对外接口：** **`emit(tree, options, *, sourcemap_out, layer, source, artifact)`**；`normalize_locations`；`_to_pyc(code, source_bytes)`（PEP-552 基于哈希的、未校验的、无源码的 `.pyc`）。
- **交互：** 调用 `lambdalift.lift_lambdas`、`rename.finalize_names`、`sourcemap.build_sourcemap`。

### `cff/gate.py`
- **职责：** 默认拒绝的白名单门控 — 拒绝 Pass 未明确允许的任何 AST 节点。
- **对外接口：** `STRUCTURAL_NODES`、`SupportSet`（`.permits`）、`GuardVisitor`、`collect_diagnostics`、**`enforce(tree, support, policy)`**。
- **交互：** 使用 `diagnostics`；由 `Pipeline` 在每个 Pass 的 `transform` 之前调用。

### `cff/diagnostics.py`
- **职责：** 共享的错误值类型。
- **对外接口：** `Severity`、`Diagnostic`（`.format()`）、`UnsupportedConstructError`。
- **交互：** 无包内导入；被 `gate` 和各 Pass 消费。

### `cff/marker.py`
- **职责：** `@local_call` 标记装饰器（运行时为恒等函数；由引擎识别并去除）。
- **对外接口：** `local_call(fn)`。
- **交互：** 由 `LocalCallPass` 处理。

### `cff/directives.py`
- **职责：** 解析 `# pyobf:` 行内源码指令，并将其绑定到最近的 `def`/`class`。
- **对外接口：** `PREFIX`、`Directive`、`extract_directives(src)`、`map_to_defs(tree, directives)`。
- **交互：** 仅使用标准库（`ast`、`tokenize`）；被需要按单元启用 / 禁用的 Pass 消费。

### `cff/analyze.py`
- **职责：** 调试可视化 — 构建流水线的 JSON 模型并渲染为独立 HTML。
- **对外接口：** **`build_model`/`analyze_html`**（CFF 视图：每作用域 CFG + 每 Pass 源码时间线），**`build_protect_model`/`protect_html`**（打包器外壳：层 / 大小细分 + 带区域注释的启动器），`build_pass_timeline`、`SCHEMA`。
- **交互：** 使用 `cfg`、`names`、`rename`、`gate`、`module_wrap`；渲染 `viz/` 资源；可选地通过 `_assemble_launcher` 接缝钩入 `protect.core`。

### `cff/sourcemap.py`
- **职责：** 从 `finalize_names` 的 `out_map` 和每作用域的 `_pyobf_scopemap` 组装 JSON 反混淆映射。
- **对外接口：** `FORMAT`、**`build_sourcemap(...)`**、`dump_sourcemap(d, path)`。
- **交互：** 使用 `names.name_meta`；在设置了 `emit_sourcemap` 时由 `emit` 调用。**绝不嵌入制品中。**

### `cff/varstore.py`
- **职责：** 调度器中变量读写的抽象（为替代存储策略提供扩展点）。
- **对外接口：** `VarStore`（Protocol）、`IdentityVarStore`。
- **交互：** `SlotVarPass` 在概念上实现了该接口。

### `cff/__init__.py`
- **职责：** 包标记（仅含文档字符串）。

### `cff/_runtime/__init__.py`
- **职责：** 空包标记（为运行时支持代码预留）。

### `cff/viz/`（包数据，非 Python）
- `analyze.js` / `analyze.css` — `analyze_html` 的前端。
- `protect.js` / `protect.css` — `protect_html` 的前端。
- 通过 `pyproject.toml` `package-data` 随包分发。

---

## `cff/passes/` — 流水线 Pass

### `passes/base.py`
- **职责：** Pass 框架：`Pass` 协议、`Pipeline` 运行器（对每个 Pass 依次执行 `enforce` 和 `transform`），以及注册表。
- **对外接口：** `Pass`（Protocol）、**`Pipeline`**（`run(tree, options)`）、`register`、`get`、`all_passes`。

### `passes/localcall.py`
- **职责：** 处理 `@local_call` 辅助函数 — 在单个调用点内联（alpha 重命名）或重命名为不透明新鲜名称；去除标记装饰器 + 死导入。
- **对外接口：** `LocalCallPass`；辅助函数 `_collect_marked`、`_AlphaRenamer`、`_WholeTreeRenamer`、`_resolve_positional`、`_remove_dead_marker_import`。
- **交互：** 最先运行；在 `supports()` 中容忍规范化前的 `match` 节点。

### `passes/dictindirect.py`
- **职责：** 将内部函数（以及常量式全局变量）引用通过每作用域的 `_D[key]` 字典（`dict_indirect`）进行路由。
- **对外接口：** `DictIndirectPass`；`_build_scope_tree`、`_collect_eligible_globals`、`_DictRewriter`。
- **交互：** 在 `StackCallPass` 之前运行，以确保其辅助基础设施不会被间接化。

### `passes/normalize.py`
- **职责：** 将 `match` 脱糖为 `if`/`elif` 链；可选的 `return_var` 改写。
- **对外接口：** `NormalizePass`；`_MATCH_NODES`、`_MatchDesugar`、`_pattern`（值 / 单例 / 捕获 / 守卫 / 或模式）、`_ReturnVar`。
- **交互：** 必须在声明规范化后白名单的 Pass 之前运行；序列 / 映射 / 类 / 星号结构模式大声报错。

### `passes/stackcall.py`
- **职责：** 将调用参数通过隐藏的 `threading.local` 压栈 / 弹栈 / 调用栈进行路由；分两个阶段（`"main"` 用于符合条件的内部 / 裸外部调用，`"post_vault"` 用于被标记的访问器调用点）。
- **对外接口：** `StackCallPass(phase=...)`；`_eligible`、`_build_preamble`、`_Rewriter`、`_StmtSplitter`、`_is_routable_marked_call`、`_PostVaultRewriter`。
- **交互：** 主阶段在 `NormalizePass` 之后；post-vault 阶段在 `DataObfPass` 之后；消费由 `ArchivePass`/`NameVaultPass` 设置的 `_pyobf_stackroute` 标记。

### `passes/slotvar.py`
- **职责：** 将安全的局部变量映射到 `_slots[i]`（`slot_vars`）。
- **对外接口：** `SlotVarPass`；`_analyze`（可槽化名称分析）、`_Rewriter`、`_slot_function`。
- **交互：** 在 `NormalizePass` 之后运行；与栈 / 数据 Pass 无顺序依赖。

### `passes/dataobf.py`
- **职责：** 用 pow/RSA 风格的分块编解码器 + `_dec` 辅助函数（`obf_strings`）加密 `str`/`bytes` 字面量。
- **对外接口：** `DataObfPass`；`_rsa_params`、`_gen_prime`/`_is_prime`（Miller-Rabin）、`_chunks_expr`、`_str_expr`/`_bytes_expr`、`_collect_skip`、`_Rewriter`、`_build_dec_helper`。
- **交互：** `_rsa_params`/`_collect_skip` 被 `ArchivePass` 复用；在改写后注入辅助函数以避免自举递归。

### `passes/flatten.py`
- **职责：** 通过 `cfg.flatten_function` 驱动对每个函数 / 方法的控制流平坦化。
- **对外接口：** `FlattenPass`；**`S1_ALLOWED`**（函数体节点白名单，由下游 Pass 的 `supports()` 共享）；`_flatten_scope`、`_flatten`、`_reject_finally`。
- **交互：** 流水线中的最后一个 Pass；将每个特性 RNG / 标志（包括证明请求）穿透传递给 `flatten_function`。

### `passes/archive.py`
- **职责：** 将所有符合条件的字面量汇入一个分层加密 blob + `_get(off,sz,c,cast)` 访问器（`const_archive`）。
- **对外接口：** `ArchivePass`；`_Collector`、`_eligible_value`、`_serialize`/`_deserialize`、`_build_archive`、`_emit_runtime`、`_RUNTIME_TMPL`（必须与 `protect/cipher.py` 中的 `_ks_xor`/`_kdf` 保持镜像同步）。
- **交互：** 在 `NameVaultPass` 之后运行（遵守 `_pyobf_no_archive`）；将 `_get(...)` 调用标记为 `_pyobf_stackroute` 以供 post-vault 栈 Pass 使用；复用 `dataobf._rsa_params`/`_collect_skip`。

### `passes/cmphide.py`
- **职责：** 用 `splitmix64(zigzag)` 摘要 + `_h(x)` 辅助函数（`hide_compares`）隐藏整数 `==`/`!=` 常量。
- **对外接口：** `CmpHidePass`；`_mix_zz`（构建侧双射，必须与生成的 `_h` 匹配）、`_eligible`、`_HELPER_TMPL`、`_Rw`。
- **交互：** 在 `FlattenPass` 之前运行，以确保从不触碰调度器中的 `state == k` 比较。

### `passes/localrename.py`
- **职责：** 通过两阶段作用域分析，将用户参数 / 局部变量 / 推导式目标重命名为新鲜名称（始终开启）。
- **对外接口：** `LocalRenamePass`；**`rename_simple_helper_locals(tree, namer=None)`**（被注入辅助函数的地方复用：archive、lambdalift、stackcall、dataobf）；`_build_scope_tree`、`_function_is_unsafe`、`_decide_renames`、`_Rewriter`。
- **交互：** 对用户代码在 `FlattenPass` 之前运行；跳过使用 `locals`/`vars`/`exec`/`eval`/`global`/`nonlocal`/`**kwargs` 的函数；保留 `self`/`cls` 和以关键字方式调用的参数。

### `passes/namevault.py`
- **职责：** 将内置名称 + 简单顶层导入（以及在启用 `name_vault_attrs` 时的属性访问）通过每模块 vault（`name_vault`）进行路由。
- **对外接口：** `NameVaultPass`；`_build_boot`（vault 自举）、`_BuiltinCollector`、`_routable_imports`、`_key_const`（将 vault 键标记为 `_pyobf_no_archive`）、`_Rw`、`_BUILTIN_NAMES`。
- **交互：** 在 `ArchivePass` 之前运行（以便 vault 的名称字符串被汇入存档）；排除 `super` / 双下划线名称 / 被遮蔽的名称 / 装饰器位置的名称。

### `passes/__init__.py`
- **职责：** 空包标记。

---

## `protect/` — Python 层保护 / 打包器

### `protect/__init__.py`
- **职责：** 保护层的公共接口 + 检测器扩展模型。
- **对外接口：** 重导出 `pack_module`（入口点）以及 `Detector`、`register`、`DETECTORS`、`build_detection`（检测器插件钩子）。

### `protect/cipher.py`
- **职责：** 纯 Python、无导入的加密原语，供构建侧（加密）和生成的启动器（解密）共享 — 必须可原样内嵌到生成的代码中。
- **对外接口：** 常量 `_TEMP_KEY`、`_SALT_SEL`、`_SALT_KEY`、`_SALT_DECOY`、`_BI_MAGIC`、`_D_MAGIC`、`_P_MAGIC`；`_kdf`（splitmix64 KDF）、`_fold`、`_ks_xor`（xorshift 密钥流 XOR；自逆）、`_hash_bytes`（FNV-1a）。
- **交互：** `_kdf`/`_ks_xor` 的运行时镜像位于 `_templates.py` 中，必须保持同步。

### `protect/astutil.py`
- **职责：** 基于 AST 的代码生成 — 从真实代码模板实例化启动器片段（无字符串拼接）。
- **对外接口：** `emit_def`、`emit_body`、`emit_expr`（模板实例化）；`xor_chain`、`add_chain`、`name`、`mul_const`、`import_stmt`；`resolve_magic`（将用户处理器的 `M.<NAME>` 连接到启动器变量）；内部类 `_Subst`。
- **交互：** 在导入时解析 `_templates.py`；在 `core` 和各检测器中广泛使用。

### `protect/templates.py`
- **职责：** 非代码生成的打包器辅助函数：格式解析、代码体 / 诱饵序列化（加密前 zlib 压缩）以及默认诱饵。
- **对外接口：** `_DEFAULT_DECOY`、`_resolve_format`、`_body_bytes`、`_decoy_bytes`。

### `protect/_templates.py`
- **职责：** **以真实 Python 函数形式编写**的启动器代码片段库（`t_*`），由 `astutil` 一次性解析后实例化（占位符被重命名 / 替换）并拼接 — 从不直接执行。
- **对外接口：** 加密运行时（`t_ks`、`t_kdf`）、密钥折叠（`t_seed`、`t_step`）、内置完整性（`t_bi_bt`/`t_bi_rel`/`t_bi_abs`、`t_capture_globals`）、blob 嵌入（`t_assign_b85`）、混淆导入（`t_obf_import`）、选择器 + exec 尾（`t_single_*`、`t_decoy_*`）、审计绊线（`t_audit_*`）、检测项（`t_detect_*`）、cohash（`t_hashfn`/`t_guard`/`t_cohash`）以及中和（`t_neuter_*`）。
- **交互：** 大写标识符是有意为之的占位符；这些函数从不被调用。

### `protect/detectors.py`
- **职责：** 检测器插件框架 — 每个检测器提供一个项（`0` 表示干净，`> 0` 表示触发），该项在 `key_binds_env` 下折叠进密钥选择器。
- **对外接口：** `Detector`（基类 / 扩展钩子：`flag`、`needs_sys`、`entry_only`、`magic_name`、`key_safe`、`term(ctx)`）、`register`（装饰器）、`DETECTORS`、**`build_detection(options, namer, poison_cell)`**；内置检测器：`TraceDetector`、`AuditDetector`、`ToolsDetector`、`EnvDetector`、`StackDetector`（仅入口）。
- **交互：** 使用 `astutil`；`_Ctx.poison_cell` 由 `core` 提供。

### `protect/outerpack.py`
- **职责：** `compress_output` 包裹层 — zlib + 滚动 XOR + b85 自举层（静态提取速度障碍 + 针对 exec 钩子剥离器的蜜罐）。
- **对外接口：** **`outer_compress(result, to_pyc, *, rounds, decoy, rng)`**（入口点）；`outer_compress_text`、`outer_compress_pyc`、`decoy_head`（无操作层，字节形状与真实轮次相同）、`_layer_src`、`_xor_encrypt`、`_b85_literal_lines`。
- **交互：** 在 `emit` 之后由 `obf_module` 调用；不依赖任何其他 `protect` 模块。

### `protect/core.py`
- **职责：** 启动器组装 + 平坦化编排 — 打包器的核心。
- **对外接口：** **`pack_module(tree, options, *, sourcemap_out, decoy_tree)`**（入口点）；`_assemble_launcher`（平坦化前的启动器 + 区域）、`_flatten_launcher`、`_emit_neuter`、`_emit_bi`、`_emit_blob_assign`、`_single_tail`、`_patch_attest_markers`、`_build_oracle_install_stmts`、`_guard_cohash`、`_choose_bi`、`_inner_fname`、`_needs_audit_cell`；盐值 `_BODY_NS_SALT`、`_DECOY_NS_SALT`（使代码体 / 诱饵 / 启动器名称相互隔离）；多模块辅助函数 **`project_s_correct(options)`**（整个项目各文件共享的种子派生选择器）、**`build_satellite(tree, options, *, module_id, s_correct, magic, dec_name_str, decoy_tree)`**（将受保护模块加密为存根 + blob）以及 **`_build_runtime_publish_stmts(...)`**（为入口生成向 builtins 发布共享 `dec` 函数与 oracle 的语句）。
- **交互：** 导入 `cipher`/`templates`/`detectors`/`astutil`/`_templates`；延迟使用 `cff.names`、`cff.attest`（包括 `dec_name`）、`cff.rename`、`cff.module_wrap` 和 `_MODULE_PIPELINE`。

### `protect/project.py`
- **职责：** 项目级多模块混淆编排。驱动单模块打包器在整个源代码树上工作，实现**核心 + 卫星**模型：一个入口模块（核心）向 `builtins` 发布共享保护运行时；受保护模块（卫星）以小型存根 + 加密 blob 的形式分发，通过该运行时解密；所有其他文件逐字复制。
- **对外接口：** **`obf_project(*, root, out, entry, protect, options, import_hook, shared_oracle_decouple)`**（主入口点，返回 `{相对路径 → 角色字符串}` 清单）；`classify_files(root, *, entry, protect)`（遍历源代码树并为每个 `.py` 文件分配 `Role`）；`Role`（枚举：`ENTRY` / `PROTECT` / `PLAINTEXT`）；内部辅助函数 `_walk_py`、`_module_id`、`_out_rel`、`_emit_to`。
- **交互：** 调用 `obf_module`（来自 `__init__`）用于入口及自包含回退构建；直接使用 `_MODULE_PIPELINE` + `wrap_module` + `emit` 进行卫星构建；依赖 `protect.core.project_s_correct`、`protect.core.build_satellite` 以及 `protect.core._build_runtime_publish_stmts`（通过 `pack_module` 中的 `publish_runtime` 路径）；读取 `cff.attest.MAGIC` 和 `cff.attest.dec_name`（发布到 `builtins` 的共享解密函数的种子派生名称）。

---

## 扩展点

- **添加混淆 Pass：** 在 `cff/passes/` 中实现 `Pass` 协议（`name`、`supports() -> SupportSet`、`transform(tree, options)`），在 `options.py` 中通过新标志控制开关，并在 `__init__.py` 的 `_FUNC_PIPELINE`/`_MODULE_PIPELINE` 中插入。所有生成的名称均使用 `Namer.fresh()`。
- **添加检测器：** 在 `protect/detectors.py` 中继承 `Detector`，用 `@register` 装饰，设置 `flag`/`magic_name`，并从 `term(ctx)` 返回一个项（0 表示干净，> 0 表示触发）。该项在 `key_binds_env` 下自动折叠进密钥；对易产生误报的信号路由到 `handler_src`（`key_safe=False`）。
- **添加启动器片段：** 在 `protect/_templates.py` 中添加 `t_*` 函数（真实 Python，大写占位符），并在 `core.py` 中通过 `astutil.emit_def`/`emit_body`/`emit_expr` 实例化。
- **添加选项：** 在 `options.py` 的 `ObfOptions`/`ModuleObfOptions` 中添加字段并附简洁的文档字符串注释，在消费处穿透传递，并在 [`OPTIONS.chs.md`](OPTIONS.chs.md) 中记录。

---

## 测试

`tests/` 包含约 2255 个差分 + 结构测试。等价测试编译原始程序和混淆后的程序，并在不同种子下比较返回值 / 异常 / 标准输出 / 参数变化；结构测试断言特定变换并拒绝回归。错误路径 / dump 回放检查在可终止的子进程中运行（错误的调度器状态可能导致无限循环）。使用以下命令运行：`.venv/Scripts/python -m pytest -q`。
