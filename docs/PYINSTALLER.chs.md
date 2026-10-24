# PyInstaller 打包

加密后的模块体会隐藏原始 `import`，PyInstaller 的静态分析无法自动收集这些依赖。`write_pyinstaller_hook` 根据**混淆前源码**生成自定义运行期 hook。导入语句放在永不调用的函数中：PyInstaller 会收集模块，但启动时不会提前导入，也不会在受保护入口上方留下 Python 调用栈帧。

## 单文件入口

```python
from pathlib import Path
from pyobfuscator import ModuleObfOptions, obf_module, write_pyinstaller_hook

source = Path("src/main.py")
out = Path("build/obf")
out.mkdir(parents=True, exist_ok=True)
options = ModuleObfOptions(output="text", pack_format="source", seed=42,
                           protect_level="full", detect_stack=True)
(out / "main.py").write_text(obf_module(source.read_text(encoding="utf-8"), options),
                             encoding="utf-8")
write_pyinstaller_hook(source, out / "pyi_rth_pyobfuscator.py")
# 运行时计算的模块名需要 extra_imports=["my_dynamic_plugin"]。
```

把需要分发、但未混淆的本地模块放到 `build/obf`，然后执行：

```text
python -m PyInstaller --onedir --paths build/obf --runtime-hook build/obf/pyi_rth_pyobfuscator.py build/obf/main.py
# 单个可执行文件改用 --onefile。
```

运行时计算的模块名需要填进 `extra_imports`。独立的数据文件和共享库仍须用 PyInstaller 的 `--add-data`、`--add-binary` 或 spec 配置。不要把待保护的原始源码目录放进 PyInstaller 搜索路径。hook 中列出的模块名可以从冻结包中恢复，即使 `obf_imports` 或 `name_vault` 在受保护源码里隐藏了它们。

PyInstaller 会把 Python 模块编译成字节码存进包里，但这不意味着能把无源码 `.pyc` 直接作为**入口脚本**。实测 PyInstaller 6.21.0 在分析本项目生成的 `.pyc` 入口时，按源码解码并报 `UnicodeDecodeError`；同一文件由 CPython 直接运行正常。如需冻结预编译的加密模块体，入口仍设 `output="text"`，并设 `pack_format="bytecode"`。该模式会锁定构建时的 Python 版本，也允许配合 `attest=True` 开启 `body_cohash=True`。TEXT 仅是外层入口，加密模块体保存的是构建时编译的字节码。

## 多文件项目

```python
from pyobfuscator import ModuleObfOptions, obf_project, write_pyinstaller_hook

options = ModuleObfOptions(output="text", pack_format="source", seed=42,
                           pack_body=True, key_from_cff=True,
                           pack_decoy=True, attest=True, detect_stack=True,
                           key_binds_env=True)
manifest = obf_project(root="src/myapp", out="build/obf", entry="main.py",
                       protect=["app/secret.py"], options=options,
                       import_hook=True)
write_pyinstaller_hook("src/myapp", "build/pyi_rth_pyobfuscator.py",
                       manifest=manifest, import_hook=True)
```

再用 `--paths build/obf --runtime-hook build/pyi_rth_pyobfuscator.py` 打包 `build/obf/main.py`。如果采用每模块存根，把两处 `import_hook` 都设为 `False`。集中导入模式下，生成的 hook 不收集已嵌入入口的卫星模块，但仍收集卫星源码中的依赖。不要让 PyInstaller 从原始目录收集这些卫星的明文源码。

## 各保护策略支持程度

下表针对 **TEXT 入口**，模块体可为源码或字节码，具体条件见各行。冻结测试环境为 Windows 11、Python 3.14.4、PyInstaller 6.21.0。“组合实测”表示在真实冻结程序中开启并运行过；“预计兼容”表示没有发现冻结环境特有的依赖，但尚未单项打包测试。

| 策略 / 选项 | 程度 | 条件与证据 |
| --- | --- | --- |
| `obf_strings`、`obf_ints`、`hide_compares` | 组合实测 | 字符串、整数和比较改写在冻结入口运行。 |
| `const_archive`、`name_vault`、`name_vault_attrs` | 组合实测 | 常量归档及名称保险库在 `onedir`、`onefile` 运行。 |
| `shuffle_states`、`opaque_predicates`、`bogus_blocks`、`bogus_clone_ratio` | 组合实测 | 默认控制流变换在两种打包模式下运行。 |
| `max_block_stmts`、`min_blocks`、`safe_mode` | 非默认值预计兼容 | 这些选项控制构建时的控制流边界；冻结测试覆盖默认值及 `min_blocks=1`。 |
| `slot_vars`、`stack_calls`、`hide_external_args`、`split_calls` | 预计兼容 | 源码层变换；未单项冻结测试。 |
| `return_var`、`dedup`、`state_delta`、`dispatch_tree`、`junk_code`、`dict_indirect` | 预计兼容 | 调度器变换；未单项冻结测试。 |
| `precompile`、`precompile_arg`、`precompile_args`、`precompile_timeout` | 预计兼容 | 发生在构建期；仅打包输出实际仍使用的依赖。 |
| `load_bytes("路径")` | 冻结实测 | 文件字节被强制放入加密归档；删除资源后构建的 `onedir` 入口仍取回字节，且 `STACKSIG 0`。生成的 hook 不收集纯标记导入。 |
| `strip_debug`、`on_unsupported`、`seed`、`emit_sourcemap` | 构建期或输出控制 | `strip_debug` 影响 AST/PYC 位置信息，而非所测 TEXT 启动器；不支持语法在打包前由 `on_unsupported` 拒绝；随机种子及源码映射不改变冻结加载。 |
| `pack_body`、`pack_format="source"` / `"bytecode"`、`key_from_cff` | 组合实测 | 两种模块体格式及派生密钥都在 `onedir`、`onefile` 运行；字节码格式锁定构建时的 Python 版本。 |
| `integrity_selfcheck`、`builtin_checks`、`builtin_spot_count` | 默认值组合实测 | 默认内置对象检查通过；自定义检查列表未测。 |
| `pack_decoy`、`decoy_src`、`decoy_obf_overrides` | 默认诱饵组合实测 | 干净路径通过；错误路径和自定义诱饵未做冻结测试。 |
| `obf_imports` | 组合实测 | 启动器的动态标准库导入在所测包中可用。 |
| `detect_trace`、`detect_tools`、`detect_env`、`key_binds_env`（`protect_level="full"`） | 组合实测 | 干净启动选择真实体；调试器、覆盖率或其他 hook 可能有意触发诱饵。 |
| `protect_level="light"` / `"full"` | `full` 组合实测；`light` 预计兼容 | `light` 是不含环境检测的 `full` 子集，未另建冻结用例。 |
| `detect_stack` | 组合实测 | `onedir`、`onefile` 和两层 `compress_output` 下信号均为 `0`，并走真实体。生成的 hook 在入口前返回；额外用 Python `exec`/`runpy` 包装入口仍会被视为外来调用。 |
| `machine_gate` 与 `detect_stack` | `onedir`、`onefile` 冻结实测 | 独立混淆的 entrance 与 `pyobfuscator_runtime` 均被收集；未授权时正文不运行，授权后进入真实路径。栈判定已计入验证包装层；`onedir` 集中导入的多文件项目也已通过。冻结 TPM 尚未实测。详见[机器验证](MACHINE.chs.md)。 |
| `attest`、`attest_density`、`attest_inflate`、`attest_target_blocks` | 默认值组合实测 | 默认互证参数在两种模式运行；自定义密度未单测。 |
| `cohash_integrity` | 有条件，组合实测 | TEXT 会锁定构建时字节码版本；两种冻结模式均使用构建解释器，换版本须重建。 |
| `body_cohash` | 有条件，组合实测 | 使用 `attest=True`、`output="text"`、`pack_format="bytecode"`；两种冻结模式均保持 `STACKSIG 0` 并运行真实体。更换 Python 版本须重建。 |
| `detect_audit`、`attest_runtime_bind`、`anti_trace_neuter` | 组合实测 | 两种模式干净启动成功；与第三方运行期 hook 的交互需按实际程序测试。 |
| `handler_src` | 只读栈信号组合实测 | 诊断处理器在两种模式打印 `STACKSIG 0`；毒化型处理器需应用级测试。 |
| `anti_trace_neuter_honeypot` | 未冻结测试 | 激进响应路径需应用级测试。 |
| `compress_output`、`compress_rounds` | 组合实测 | 两层包装在两种模式运行，栈检测计入包装帧。 |
| `require_min_python` | 预计兼容 | TEXT 明文版本门在压缩引导之前；PyInstaller 本身携带构建解释器。 |
| `obf_project` 每模块存根 | 冻结实测 | 明文包、模块及受保护卫星在 `onedir` 的源码体、字节码体均运行；字节码体包括 `body_cohash`。 |
| `obf_project(import_hook=True)` | 冻结实测 | 已嵌入的卫星不进入收集清单，由入口安装的 finder 加载；源码体、字节码体均已测试。 |
| `shared_oracle_decouple` | 未冻结测试 | 共享运行时另一种选择器绑定尚无冻结用例。 |
| `emit_pyi`、`single_file_interface`、`exports`、`exports_from_all` | 构建期接口控制 | 类型存根及导出选择并非 PyInstaller 加载机制；未做独立冻结测试。 |
| `output="pyc"` 作为入口 | 所测 PyInstaller 拒绝直接入口 | `.pyc` 本身可由 CPython 运行；PyInstaller 分析入口时产生 `UnicodeDecodeError`。冻结发行请使用 TEXT 入口加密字节码体。 |
| `output="ast"` 作为入口 | 需要先输出源码 | API 返回 AST 对象，而不是 PyInstaller 入口文件；打包前需输出 `.py`。未做独立冻结测试。 |

多文件项目中，生成器扫描完整原始源码树。表中单入口的组合测试不代表每个可选策略都在受保护卫星模块里测试过；单独的项目测试覆盖普通存根和内嵌卫星，以及源码体、字节码体。运行时计算的导入仍需填写 `extra_imports`。

这些是 Windows 冒烟结果，不等于 Linux/macOS 已验证。各目标系统需分别构建与测试，PyInstaller 可执行文件也随构建系统和解释器而定。

## 回归测试

```text
python -m pytest tests/test_pyinstaller.py -q
```

冻结集成测试需要可选依赖 `pip install -e ".[dev,pyinstaller]"`；没有 PyInstaller 时仍运行 hook 生成的单元测试。测试和打包过程需要可写的构建及临时目录。
