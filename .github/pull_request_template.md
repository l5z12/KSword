## Problem and change / 问题与修改

<!-- Explain the observable problem and resulting behavior. Link an issue if relevant.
     For a refactor, name the responsibility boundary and preserved behavior.
     可用中文或英文填写；小修复不要求先创建 Issue。 -->

## Validation / 验证

<!-- List actual commands and results, including toolset/configuration for native
     builds. State what was not tested. Compilation, help tests, and source checks
     do not imply driver loading or runtime acceptance. -->

## Related updates / 相关同步

<!-- Keep only items relevant to this change. -->
- [ ] New/moved sources are in every consuming project and filters file.
- [ ] CLI command/help changes update CliHelp.cpp, regenerate docs/cli.md, and update docs/zh-CN/cli.md.
- [ ] Public guide changes update both English and Chinese copies and pass the docs check.
- [ ] Visible text changes update both language packs and pass the i18n audit.
- [ ] Changed behavior has relevant regression coverage, or the validation limitation is explained.
