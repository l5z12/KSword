# 文档目录

[English](../README.md) · [项目首页](README.md)

主要公开指南以英文为主，并提供中文副本。先阅读贡献指南、构建指南和代码地图，
再进入对应子系统；无需安装或加载驱动就能运行入门测试。

## 指南

| 主题 | English | 中文 |
| --- | --- | --- |
| 项目概览 | [English](../../README.md) | [中文](README.md) |
| 贡献指南 | [English](../../CONTRIBUTING.md) | [中文](contributing.md) |
| 代码风格 | [English](../coding-style.md) | [中文](coding-style.md) |
| 构建与环境 | [English](../development.md) | [中文](development.md) |
| 代码地图与维护 | [English](../maintenance.md) | [中文](maintenance.md) |
| 测试 | [English](../../tests/README.md) | [中文](testing.md) |
| 脚本 | [English](../../scripts/README.md) | [中文](scripts.md) |
| 构建目录 | [English](../../build/README.md) | [中文](build-layout.md) |
| 发行包 | [English](../releasing.md) | [中文](releasing.md) |
| Agent 工作约定 | [English](../../AGENTS.md) | [中文](agent-notes.md) |
| CLI 参考 | [English](../cli.md) | [中文](cli.md) |
| 语言包 | [English](../language-packs.md) | [中文](language-packs.md) |
| 动态偏移接入 | [English](../dyndata.md) | [中文](dyndata.md) |
| 插件规范 | [English](../plugins.md) | [中文](plugins.md) |
| 桌面绘制 | [English](../desktop-drawing.md) | [中文](desktop-drawing.md) |
| 系统内存审计 | [English](../memory-audit.md) | [中文](memory-audit.md) |
| 内核知识中心 | [English](../kernel-knowledge.md) | [中文](kernel-knowledge.md) |
| 窗口输入 | [English](../window-input.md) | [中文](window-input.md) |
| IOCTL 审计 | [English](../ioctl-audit.md) | [中文](ioctl-audit.md) |

## 专题参考

以下现有专题仍为中文原文，并非已经完成的英文译本。

- [Feature internals / 功能技术参考](feature-reference.md)
- [Feature tooltips / 功能提示词典](feature-tooltips.md)
- [Virtualization reference / 虚拟化规范](virtualization-reference.md)
- [Virtualization roadmap / 虚拟化路线图](virtualization-roadmap.md)
- [DWM ordering / DWM 窗口序列](dwm-z-order.md)
- [RXPF experiments / RXPF 实验](rxpf.md)
- [Forensics backends / 取证后端](forensics-backends.md)
- [UI table details / UI 表格详情](ui-table-details.md)

研究记录保留原始语言和上下文： [research](../research) [next](../next) [pdb_r0_audit_prep](../pdb_r0_audit_prep).

## 文档维护

新增主要指南使用 ASCII 小写连字符文件名；英文放在 `docs/`，中文放在 `docs/zh-CN/`。
常规根文档（README、CONTRIBUTING、AGENTS）保留在根目录。两种语言互链，并在
`docs/catalog.json` 登记。行为或命令变化在同一 PR 同步两份；CLI 英文命令目录由
`tools/generate_cli_docs.py` 生成，中文保留操作说明。不要把未翻译的文件标记成英文版。
移动文档时更新内部链接、项目/脚本引用和配对清单。
运行 `python tools/check.py --check docs --check cli-docs` 检查链接、配对与 CLI 文档时效。
图片放 `docs/assets/`；研究原始记录放 `docs/research/`；生成报告、PDF、日志放忽略的
`artifacts/`，发行包放 `dist/`，不要放进仓库根目录。
