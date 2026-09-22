# 历史源码归档

[English](../../archive/README.md) · [当前目录结构](repository-layout.md)

这些文件保存旧实验和已停用的构建描述，不是受支持的构建入口。
当前解决方案是根目录的 `KSword.sln`，单个目标使用 `tools/dev.py`。

- `archive/desktop/`：未使用的旧 Qt 窗体模板和 Win32/qmake 构建描述，使用文本扩展名，
  避免被 IDE 和检查工具误认为活动工程。
- `archive/taskbar/`：保留供参考的历史任务栏源码快照。

当前实现应放在对应模块中，普通备份应使用 Git 历史。
