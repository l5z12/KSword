# 测试

[English](../../tests/README.md) · [构建指南](development.md)

使用 `uv run --python 3.12 python tools/check.py` 运行源码检查。
Windows 上运行 `uv run --python 3.12 python tools/dev.py test` 执行三组入门原生测试。
需要 MSVC 和 Windows SDK，不需要 Qt、WDK、管理员权限或已加载驱动。

| `tests/native/` 下的项目 | 覆盖范围 | runner 目标 |
| --- | --- | --- |
| `KswordArkClientTests` | 驱动响应边界、部分结果、句柄所有权 | `client-tests` |
| `KswordCliTests` | 数值与十六进制参数解析 | `cli-tests` |
| `KswordFsDecodeTests` | 损坏的 NTFS run list | `fs-tests` |
| `KswordMonitorTests` | ETW 配置验证与往返，需要 QtCore | `monitor-tests` |
| `KswordARKLightTests` | 离线证据、交叉视图、快照、DDMA 计划等分析辅助逻辑 | MSBuild 构建 `.vcxproj` 后执行产物 |

单独运行使用 `python tools/dev.py test --target <target>`；runner 先构建，失败即停止。
ARKLight 离线测试项目不嵌入也不加载驱动：

```powershell
# 在可使用 MSBuild 的 Visual Studio 开发者终端中，从仓库根目录执行。
MSBuild tests/native/ark_light/KswordARKLightTests.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64 /m:1
if ($LASTEXITCODE -ne 0) { throw 'Test build failed.' }
& ./tests/native/ark_light/x64/Release/KswordARKLightTests.exe
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
```

Python 工具测试保留在 `tools/tests/`；独立组件测试（例如 `tests/native/dwm_z_order/`）
仍随组件构建。`python tools/dev.py test --target cli` 构建 CLI 并执行所有已声明帮助路由，
不会执行相应系统操作。回归测试应放在能重现问题的最小行为边界，新增原生源码同时登记
项目和 filters。产物位于项目内忽略的 `x64/<configuration>/`。
驱动实机、VM 和签名验收独立报告；离线通过不证明硬件支持。
