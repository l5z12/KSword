# KSword agent 工作约定

[English](../../AGENTS.md) · [贡献指南](contributing.md) · [代码地图](maintenance.md)

## 开始工作前

同时读取当前平台可用的个人/用户记忆或会话摘要，以及
[共享记忆索引](../../.claude/memory/MEMORY.md)，再按任务阅读相关主题。
`.claude/memory/` 供所有 agent 和开发者共享；没有个人记忆不能作为跳过共享记忆的理由。
修改主程序 UI、主题或窗口背景前，先读
[UI 架构](../../.claude/memory/ksword-ui-architecture.md)。把可复用经验写回对应主题。
文档和规则使用仓库相对路径，不以个人机器的绝对路径作为开发落点。

## 代码与文档边界

- 遵循 `docs/coding-style.md`：类型 PascalCase，函数和变量 camelCase，常量
  kPascalCase；脚本帮助与诊断使用英文。保留外部规定的名称、通信契约和本地化输入模式。
- 第一方代码注释使用英文。保留技术标识符、字面量示例、第三方声明与安全不变量含义；
  用户可见字符串和双语文档仍遵循各自语言规则。
- R0/R3 协议只在 `shared/driver/` 定义。
- IOCTL handler 只在 `drivers/ark/src/dispatch/ioctl_registry.c` 注册；
  `ioctl_dispatch.c` 不承载业务 switch。
- KswordARK 设备访问只通过 `shared/ark_client/`；
  Dock UI 不直接调用 KswordARK `DeviceIoControl`。
- 新源码同步加入所有消费它的 `.vcxproj` 与 `.vcxproj.filters`。
- CLI 命令、别名、参数变化同步内置 help 元数据，运行
  `tools/generate_cli_docs.py` 更新 `docs/cli.md`，并更新 `docs/zh-CN/cli.md`。
- 主要公开文档以英文为主，并在 `docs/zh-CN/` 提供中文副本；同一改动同步两种语言，
  在 `docs/catalog.json` 登记配对。研究记录保留原始语言。
- 语言包只能定点编辑；禁止使用 `json.load`/`json.dump` 或其他序列化器整体重写。
- 主程序可见文本变化同步 `apps/desktop/languages/zh-CN.json` 和
  `en-US.json`，通过 `python tools/check.py --check i18n`。
- 保留第三方原始许可证及署名。

运行 `python tools/check.py` 及相关原生测试。本地 Python 可以使用
`uv run --python 3.12 python`；CI 可以直接调用 Python。
依赖和显式工具集选择见[构建指南](development.md)。

## 发行与构建恢复

打包前阅读[发行流程](releasing.md)，保持完整 `Release/` 布局，更新必需二进制，
包含许可证、配置，并验证归档完整性及内容。复用驱动必须明确记录。
遇到 `LNK1000`、`IMAGE::BuildImage` 或 `.iobj` 内部链接错误，按
[恢复说明](../../.claude/memory/ksword-build-recovery.md) 仅进行一次临时关闭 WPO/LTCG
的干净重建，不自动更换编译器或工具集，随后只验证产物。
WDK 链接后校验、完整构建、签名、加载分别报告；停止卡住的 MSBuild 前，必须确认
具体 PID 且没有活跃编译器、链接器或验证器子进程，只停止该一个进程。

## Launcher 用户报告接入

先只读验证解压后的报告，确认 `valid=true` 后才提交语料库：

```powershell
uv run --python 3.12 python tools/pdb_offset_generator/launcher_report_intake.py $reportDir
uv run --python 3.12 python tools/pdb_offset_generator/launcher_report_intake.py $reportDir --corpus-root $corpusRoot --commit
```

工具校验 SHA256 与 PE/RSDS 身份，下载精确 PDB，生成 NTOS/NTKRLA57 偏移；
collection-only 模块只保存 PE/PDB。Wine、非 amd64、缺少 RSDS、校验和不匹配报告
不得进入正式矩阵。导入后运行 `ksword_profile_release_sync.py` 重新生成唯一发布矩阵
`ark_dyndata_pack_v4.json`，再运行 `apps/launcher/tools/generate_support_manifest.py`。
确认 PDB GUID/Age 唯一且 `complete=true`，构建 Launcher Release；重复导入应返回 `existing`。
