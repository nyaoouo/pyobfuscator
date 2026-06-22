# pyobfuscator

一个**源码级 Python 控制流扁平化混淆器**，并附带一套可选的、分层的
**Python 层软件保护栈**（压缩+加密壳 → 控制流派生密钥 → 分支无关诱饵 → 反 trace 蜜罐 → 混淆 import → cff↔python 运行期互证）。

> 英文版: [`README.md`](README.md) · 选项: [`docs/OPTIONS.chs.md`](docs/OPTIONS.chs.md) ·
> 架构: [`docs/ARCHITECTURE.chs.md`](docs/ARCHITECTURE.chs.md)

每一项变换都经过**对 CPython 的差分等价门校验**：在未被篡改的路径上，混淆/打包后的程序与原程序
**行为完全一致**（返回值、异常类型+消息、stdout、参数变更，跨多个 seed）。整体是 **fail-loud**
的：默认拒绝的白名单门会拒绝任何它无法证明可保持语义的构造。输出对给定的源码 + seed + flag 组合是**确定性的**。

> **诚实的威胁模型。** 纯 Python 保护是**混淆级，而非密码学级**：解密例程必然出现在可见的启动器
> 代码里，因此铁了心的*动态*攻击者（调试器、`exec`/`compile` 钩子，或被 patch 的解释器）只要在
> *活跃的* `exec(body)` 处 dump 内存就能取胜。运行期**互证（attestation）**确实堵住了*离线*变体——
> 把 body blob dump 出来、脱离启动器 oracle 重放会发散——但*进程内活跃 dump* 仍是原生 /
> 驱动层（本层不涉及）的职责。本层的价值在于：大幅抬高静态阅读、自动化抽取（如基于 `sys.settrace` 的
> codec 抠取）、调试器、覆盖率工具、AI 逆向的成本——并把"侦测"变成**蜜罐**。

---

## 依赖要求

- Python **3.11+**（混淆器本身及其输出均如此）。完整的 TEXT 栈已在 3.12 和 3.14 上验证。
- 无运行时依赖。测试套件需要 `pytest`（`pip install -e .[dev]`）。

## 快速上手

```python
from pyobfuscator import obf_module, ModuleObfOptions

src = "import sys\nFLAG = 'secret'\ndef ok(k):\n    return k == FLAG\n"

# 1) 混淆后的源码（跨 Python 版本可移植）
text = obf_module(src, ModuleObfOptions(output="text", seed=1, min_blocks=1))

# 2) 无源码 .pyc 字节串（紧凑；锁定到构建解释器版本）
pyc = obf_module(src, ModuleObfOptions(output="pyc", seed=1, min_blocks=1))

# 3) 完整保护：加密 body + 控制流密钥 + 诱饵 + 互证
hardened = obf_module(src, ModuleObfOptions(
    output="text", seed=1,
    pack_body=True, key_from_cff=True, pack_decoy=True,
    integrity_selfcheck=True, attest=True, obf_imports=True,
))
```

- `obf_module(src, opts)` 返回混淆后的**源码**（`output="text"`）、**.pyc** 字节串
  （`output="pyc"`），或 **`ast.Module`**（`output="ast"`）。`obf_func` 对单个函数执行相同操作。
- `output="pyc"` 产物是符合 PEP-552 哈希式、免校验、**无源码**的 `.pyc`：命名为
  `<module>.pyc` 后既可直接运行（`python <module>.pyc`）也可导入（`import <module>`）。命名时可使用
  `cache_tag()` / `sourceless_pyc_name(module)` 辅助函数。

### `protect_level` 预设档

无需逐一设置保护 flag：

- `"off"`（默认）—— 使用单独 flag。
- `"light"` —— 加密壳 + 控制流密钥 + builtin 完整性 + 诱饵 + 混淆 import（仍可调试）。
- `"full"` —— `light` + 反 trace 蜜罐（加载时检测到调试器 / `settrace` / 覆盖率工具 → 诱饵）。

```python
obf_module(src, ModuleObfOptions(output="pyc", seed=1, protect_level="full"))
```

每个选项的作用、影响及限制，详见 **[`docs/OPTIONS.chs.md`](docs/OPTIONS.chs.md)**。

### 多模块项目

`obf_project` 可以一次性混淆整个源代码树：一个入口模块向 `builtins` 发布共享解密运行时；每个受保护模块以轻量级存根 + 加密 blob 的形式分发，并通过该运行时解密。明文文件逐字复制。

```python
from pyobfuscator import obf_project, ModuleObfOptions

manifest = obf_project(
    root="src/myapp",
    out="dist/myapp",
    entry="main.py",                          # 发布共享运行时
    protect=["app/secret.py", "app/logic.py"],# 作为卫星混淆
    # app/__init__.py 未列出 → 逐字复制为明文
    options=ModuleObfOptions(
        output="pyc", seed=42,
        pack_body=True, key_from_cff=True,
        attest=True, pack_decoy=True,
    ),
)
# 运行：python dist/myapp/main.pyc
# 导入同样有效：import app.secret   （透明加载 app/secret.pyc）
```

可运行的演示位于 `sample/project_test/`（通过 `build_project.py` 构建）。完整参数说明（包括 `import_hook` 和 `shared_oracle_decouple`）详见 **[`docs/OPTIONS.chs.md`](docs/OPTIONS.chs.md)**。

### 构建期常量（`precompile` / `precompile_arg`）

两个标记函数可在构建期将计算结果作为加密常量折叠到混淆产物中。运行时两者均为恒等 / 返回默认值，未混淆的源码可正常运行。

```python
from pyobfuscator import precompile, precompile_arg, obf_module, ModuleObfOptions

def _scramble(text):
    return tuple((ord(c) + i * 3) % 256 for i, c in enumerate(text))

def license_ok(key):
    # 构建期：_scramble("PROD-KEY") 被求值；结果元组被折叠进来并加密。
    # 输出的常量侧不出现密钥字面量，也不出现 scramble 算法。
    return _scramble(key) == precompile(_scramble(precompile_arg("LICENSE_KEY")))

out = obf_module(open("secret.py").read(), ModuleObfOptions(
    precompile_args={"LICENSE_KEY": "PROD-KEY-1234"},
    const_archive=True,
))
```

- **`precompile(expr)`** — 在构建期（隔离子进程中）对 `expr` 求值，并将调用替换为结果常量。`expr` 必须在模块作用域可求值（不能是函数参数）。
- **`precompile_arg("KEY")`** — 必填形式：替换为 `precompile_args["KEY"]`；若缺失则构建大声报错。**`precompile_arg("KEY", default)`** — 可选形式：`"KEY"` 不存在时使用 `default`。密钥仅存在于构建脚本中，源码中不会出现。
- **`ObfOptions.precompile_args`** — 传递给 `obf_func` / `obf_module` / `obf_project` 的注入值字典。

折叠后的常量随即流经 `const_archive` / `obf_ints` / `obf_strings` 并被加密。完整参考（包括显式报错条件和确定性说明）详见 **[`docs/OPTIONS.chs.md`](docs/OPTIONS.chs.md)**（§0）。

---

## 功能一览

**`cff/` —— 控制流扁平化引擎。** 每个函数 / 方法 / 模块体均变为 `while True` 状态机
dispatcher。已支持：函数、嵌套函数 + 闭包、类方法（MRO / `super` / `property` / `classmethod` 均保留）、模块体、`try/except/else`、`try/finally`、`with`、列表推导式 + lambda、`match`（→ if 链）、海象运算符、`assert`。加固手段：随机 state id、opaque predicate 族、bogus 块（克隆自真实代码）、state 加密整型常量、常量归档、builtin/import 名称保险库、字符串/整数 codec、调用参数隐藏、slot 变量、BST dispatch 等。
`yield`/生成器/`async` 不支持（会 fail-loud 拒绝）。

**`protect/` —— Python 层保护。** `pack_module` 将混淆后的模块替换为一个启动器，该启动器以
压缩+加密 blob 携带 body，并在运行时重建：

- **加密壳 + 控制流密钥** —— 解密密钥由启动器自身的正确执行路径派生，因此篡改控制流会得到错误密钥。
- **分支无关诱饵** —— 真 body 与诱饵 body 共享同一密文；选择通过 `dict.get` + 算术实现，无可 patch 的布尔判断。篡改/走错路时干净地解出诱饵。
- **完整性** —— builtin 身份校验与 guard-`co_code` 哈希折进密钥（monkeypatch / 字节码 patch → 诱饵）；使用 PYC 时，body 可自验证其 `co_code`。
- **侦测 → 诱饵** —— `settrace`/profiler、调试器/覆盖率模块、被替换的 breakpointhook /
  inspect 模式，或外来的 `exec`/`import` 入口，均折进密钥（蜜罐，opt-in）。
- **运行期互证** —— 启动器向 body 的 globals 中安装一个 oracle；门控 dispatcher 跳转依赖它，因此脱离启动器 dump 出来的 body 会发散（击败离线 dump-and-replay）。
- **混淆 import**、**压缩输出**（zlib + rolling-XOR + b85 bootstrap），以及**最低版本检测**，共同构成发布包的外层封装。

完整的逐模块结构图及扩展点，详见
**[`docs/ARCHITECTURE.chs.md`](docs/ARCHITECTURE.chs.md)**。

---

## 仓库布局

```
pyobfuscator/
├── src/pyobfuscator/      # 包：cff/（引擎）+ protect/（壳）+ 根 API
├── tests/                 # ~2,255 个差分 + 结构测试
├── docs/
│   ├── OPTIONS.md         # 各选项参考（作用 / 影响 / 限制）
│   └── ARCHITECTURE.md    # 逐模块结构图 + 扩展点
├── README.md  /  README.chs.md
└── pyproject.toml
```

## 测试

```bash
.venv/Scripts/python -m pytest -q        # Windows venv 布局（POSIX 下用 bin/）
```

测试套件分为差分测试（编译原始版与混淆版，对比跨多个 seed 的行为）和结构测试（断言特定变换是否存在）。错误路径 / dump-replay 检查在可终止的子进程中运行，因为错误的 dispatcher 状态可能导致死循环。
