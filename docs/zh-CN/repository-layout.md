# 仓库目录结构

[English](../repository-layout.md) · [编码风格](coding-style.md) · [代码地图](maintenance.md)

Windows 应用的解决方案入口为 `KSword.sln`，单个开发目标可以通过
`tools/dev.py` 构建。源码目录按职责划分，产品版本和 CPU 架构属于构建配置。

| 位置 | 职责 |
| --- | --- |
| `apps/desktop/` | Qt 桌面程序，各个 Dock 独立成模块 |
| `apps/cli/` | 命令行前端 |
| `apps/ark_light/` | 原生轻量前端 |
| `apps/launcher/`、`apps/setup/` | 启动兼容性和安装器 |
| `apps/taskbar/`、`apps/hud/`、`apps/uac_desktop/` | 配套应用 |
| `drivers/ark/` | 内核实现和驱动专用测试 |
| `integrations/` | API 监视、DWM 代理和 Cheat Engine 集成 |
| `shared/ark_client/` | 多个前端共享的驱动传输和领域客户端 |
| `shared/driver/` | 唯一的 R0/R3 协议声明 |
| `shared/evidence/` | 与前端无关的证据处理 |
| `shared/platform/` | 可复用平台工具，部分模块还需要 Qt Core |
| `tests/native/` | 按主题组织的原生回归测试 |
| `tools/`、`scripts/` | 源码检查、开发工具和操作脚本 |
| `build/msbuild/` | 共享构建配置 |
| `third_party/` | 第三方依赖和署名 |
| `docs/`、`docs/zh-CN/` | 英文主文档和对应中文副本 |
| `docs/archive/`、`archive/` | 历史文档和源码快照 |
| `artifacts/` | 不入库的构建产物、审计报告和本地实验 |

## 文件和目录命名

- 自有源码目录使用小写 `snake_case`，如 `process_dock`、`ark_client` 和
  `api_monitor`。使用领域名称，避免临时编号、产品版本或开发者姓名。
- C++ 类型和模块文件使用 PascalCase，如 `ProcessSnapshot.h/.cpp`。
  按职责拆分时使用 `Type.Responsibility.cpp`，私有辅助头使用 `Type.Support.h`。
- C 驱动模块使用小写 `snake_case`，如 `ioctl_registry.c/.h`。
  头文件与实现放在同一个模块目录中。
- 保留 `main.cpp`、`pch.h`、`resource.h`、`CMakeLists.txt`、`README.md`、
  `AGENTS.md` 等约定俗成的入口和配置文件名。
- Python 使用 `snake_case.py`，PowerShell 公共命令保留 `Verb-Noun.ps1`，
  文档使用语义清晰的 `kebab-case.md`。
- 保留第三方文件名、原始语言研究记录、资源标识和安装后应用使用的文件名。
  源码目录重命名不得悄悄改变可执行文件、DLL、协议或资源 URL。

新增源码必须注册到所有消费者的 `.vcxproj` 和 `.filters`。修改工程输入后运行 `uv run --python 3.12 python tools/project_filters.py --write`，
让虚拟目录跟随实际目录、头文件和实现保持在一起，共享输入按仓库路径分组。
`tools/check.py` 会拒绝过期的 filters。Windows 上也必须使用
精确大小写。同步更新 include、资源清单、CI 路径过滤、脚本和双语指南。

## 构建产物

应用和驱动统一输出到 `artifacts/bin/<platform>/<configuration>/`，
例如 `artifacts/bin/x64/Release/`。原生测试产物位于对应测试工程的
已忽略 `x64/Release/` 目录。中间文件、本地 SDK、签名私钥和 `.vcxproj.user`
配置不得入库。根目录只保留解决方案、仓库规则和自动加载的 MSBuild 配置。
