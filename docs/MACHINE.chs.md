# 机器验证入口

启用 `ModuleObfOptions(machine_gate=MachineGateOptions(...))` 后，构建器用 AES-256-GCM 加密完整的入口产物。内容密钥只交给构建方传入的 `machine_record_out`，不写入分发文件。运行时先执行独立混淆的 `entrance` 文件，以 `interact_func(challenge: bytes) -> bytes` 获取凭证；签名、设备密钥解封和正文认证全部成功后才执行主脚本。失败调用 `on_fail()`；即使它返回，也会停止。

首版支持 Windows TPM（`device_policy="tpm_required"`）和明确选择的弱软件密钥模式（`"software_allowed"`）。需在构建与目标环境安装 `pyobfuscator[machine]`；程序运行时只导入 `pyobfuscator_runtime` 与 `cryptography`。在线模式每次生成随机 challenge；离线模式须提供固定的 `offline_nonce`，许可证可以重复使用。

服务端调用 `pyobfuscator.machine.solve_challenge(...)`，凭发行方 RSA 私钥解出完整请求字段，再用 Ed25519 私钥签发把内容密钥封给设备公钥的响应。服务端还必须保存构建时产生的内容密钥，并自行实现设备登记、授权和需要的重放控制。Windows TPM 模式的 `hardware_id` 是 TPM EK 公钥指纹，与应用设备密钥指纹分开；软件模式使用可复制密钥的指纹。请求不含 TPM 证明，因此仅凭该字段不能确认客户端真的使用 TPM。

多文件项目的受保护模块要求共享运行时、`attest=True` 和 `import_hook=True`，模块 blob 随入口一起被外层加密；原本分类为明文的文件仍然明文。PyInstaller 的 TEXT 入口及 `detect_stack` 已做 onedir、onefile 实测，集中导入的多文件项目已做 onedir 实测。已授权机器执行时，内容密钥与 Python 明文仍会进入进程内存，不能阻止该机器上的动态提取。

完整构建和服务端示例、接口边界及遗留风险见 [English guide](MACHINE.md)。
