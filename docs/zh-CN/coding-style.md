# 代码风格

[English](../coding-style.md) · [贡献指南](contributing.md)

KSword 的第一方 C/C++ 标识符采用统一命名。名称应说明业务含义和操作；仅修改
大小写不能提升可读性。新变量不要使用 `dw`、`lp`、`psz`、`b` 等类型前缀。

| 标识符 | 规则 | 示例 |
| --- | --- | --- |
| 类、结构体、联合体、枚举、类型别名 | PascalCase | `ProcessSnapshot` |
| 函数、方法 | camelCase | `readProcessSnapshot` |
| 变量、参数、公开数据成员 | camelCase | `processId` |
| 私有数据成员 | camelCase 加末尾下划线 | `deviceHandle_` |
| 常量、枚举值 | kPascalCase | `kMaximumEntries`、`State::kReady` |
| 命名空间 | 小写；多词可用下划线 | `ksword::evidence` |
| 预处理宏 | UPPER_SNAKE_CASE | `KSWORD_ENABLE_TRACE` |

新名称中的缩写按普通单词处理，如 `readIoctl`、`processId`、`parseJson`。用类型和
接口约定表达所有权、可空性，不要只靠前缀。构造和析构函数保留类名，运算符保留
C++ 语法。参数即使带 `const` 或默认值，也使用 camelCase。

## 兼容性边界

外部接口规定的名称沿用原拼写，包括 Windows/WDK 声明和回调、Qt 重写和自动连接
槽、导出入口、汇编链接、第三方接口，以及 `shared/driver/` 中已发布的通信声明。
保留序列化键、命令名称、协议常量、符号查询字符串和资源 ID。这些属于兼容性约定，
不应成为新私有实现的命名范例。

重命名必须同步声明、定义、调用、测试和相关文档，并检查字符串分派和代码生成器。
不要对常见标识符做全局文本替换：同一拼写可能指向不同声明或 Windows 结构成员。

## 工具

根目录 `.clang-tidy` 通过 `readability-identifier-naming` 记录规则。使用真实目标的
编译数据库运行检查，包含其 Windows SDK、WDK、Qt、宏和包含目录。应用修改前审查
建议；解析失败不能视为检查通过。检查局部名称和已有常量的冲突、宏参数
（`FIELD_OFFSET`、SAL、WDF）、汇编 `PROC` 符号、导入变量和第三方前置声明。
仅完成源码重命名不足以验证这些边界。Clang 仅用于分析，正常构建仍使用
[构建指南](development.md) 中明确选定的 MSVC 工具集。

重命名后构建所有受影响的消费者并运行原生测试，再执行
`uv run --python 3.12 python tools/check.py`。即使源码检查通过，名称变化仍可能破坏
链接或 Qt 分派。

## 脚本语言

第一方脚本的注释、帮助、诊断、进度、提示和开发报告使用英文。Python 沿用 PEP 8，
PowerShell 的公开命令沿用 `Verb-Noun`，不套用 C++ 大小写规则。

作为输入数据的非英文内容应保留：匹配本地化 Windows 输出的模式、Unicode 回归
样例、双语文档内容和既有持久化值。用英文解释例外。不要翻译必须识别中文 Windows
输出的正则，也不要在翻译诊断信息时静默迁移存储格式。

`python tools/check.py --check script-language` 检查脚本和工作流代码。
`tools/script_language_exceptions.json` 列出字面量数据的精确行和保留理由，不是未翻译
消息的宽泛基线。同一脚本中即使有合理的输入模式例外，新诊断仍必须使用英文。

## 文件和目录名

遵循[仓库目录结构](repository-layout.md)：C++ 模块使用 PascalCase，C 模块和源码目录使用 snake_case，并保留常规入口文件名。
