# 发行包制作

[English](../releasing.md) · [文档目录](index.md)

在仓库根目录操作，包内根目录必须为 `Release/`。`$ReferenceArchive` 必须由维护者明确提供，不能假定其他开发者拥有某个历史包。已有暂存目录必须先检查，避免误删文件。

每条构建命令后检查 `$LASTEXITCODE`，非零立即停止；不要把前面失败、最后一条成功当成
整套成功。ARKLight 完整链接需要嵌入驱动，进包的 ARKLight 必须是对应版本产物。
若复用现有驱动，记录其身份和来源，不声称为本次新构建。下文的本地构建恢复 helper
并非公开仓库依赖，只有已安装时才可调用。

## 1. Release 构建

在仓库根目录执行。先通过 `tools/dev.py doctor --target desktop` 确认 MSBuild 和 Qt 路径。下面的 `$msbuild`、`$env:KSWORD_QT_DIR`、`$qtMsBuild` 使用该输出中的实际路径。主程序、Launcher、Taskbar、KswordHUD 和 APIMonitor_x64 必须重新构建并覆盖进包。

```powershell
# 将 doctor 输出的路径赋给 $msbuild、$env:KSWORD_QT_DIR 和 $qtMsBuild。

& $msbuild 'apps\desktop\KswordDesktop.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal
& $msbuild 'apps/launcher\Launcher.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m:1 /v:minimal
& $msbuild 'apps/taskbar\Taskbar.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal
& $msbuild 'apps/hud\KswordHUD.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /p:QtMsBuild=$qtMsBuild /m:1 /v:minimal
& $msbuild 'integrations/api_monitor\APIMonitor_x64.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 /m:1 /v:minimal
```

### 主程序 `LNK1000` / `IMAGE::BuildImage` 恢复

如果主程序的 MSVC 链接日志包含 `LNK1000`、`IMAGE::BuildImage` 或 `.iobj`，不要改用 LLVM、`amd64\MSBuild.exe`、替代 TargetName，也不要自动升级或降级 MSVC。先且仅执行一次干净重建，并仅对这次构建禁用 Whole Program Optimization：

```powershell
& "$env:USERPROFILE\.codex\skills\ksword-build-check\scripts\Invoke-KSwordBuildCheck.ps1" `
  -RepositoryRoot (Get-Location).Path `
  -Action Rebuild `
  -DisableWholeProgramOptimization
```

该兼容开关只在本次构建使用的临时 props 中关闭 WPO/LTCG，不改动工程文件。成功必须同时满足 `BUILD_RESULT=SUCCESS`、`EXIT_CODE=0`，且 `artifacts/bin\x64\Release\Ksword5.1.exe` 非零；随后不要为了“复查”立刻再跑普通 Build（WPO 禁用会使常规增量缓存失效），需要时只用 `-VerifyArtifactOnly`。只有该恢复路径也复现失败后，才考虑安装 VS servicing update 或并列 v143 工具集。

### 驱动 WDK x64 `ApiValidator` 后置校验

驱动仍由标准 MSVC/WDK 构建。若 `KswordARK.sys` 已在链接阶段更新、但 WDK 后置阶段因错误选择 ARM64 `ApiValidator`/`aitstatic` 或无子进程的静默卡住，不得把被中止的 `/t:Build` 说成整体成功：先确认实际报错发生在链接之后，记录精确 MSBuild PID/命令行，并确认没有活跃的 `cl.exe`、`link.exe` 或验证器子进程，才可以停止该**唯一**卡住的 MSBuild。

随后以 x64 验证器单独校验刚链接的 `.sys`：

```powershell
$solutionDir=(Resolve-Path 'Ksword5.1').Path + '\'
$apiValidatorX64='C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64'
& $msbuild 'drivers/ark\KswordARKDriver.vcxproj' /t:ApiValidator `
  /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=$solutionDir `
  /p:ApiValidator_ApiExtractorExePath=$apiValidatorX64 /m:1 /v:minimal
```

`Driver is 'Universal'.` 是该独立验证的通过标志。它只证明已链接驱动的 API/体系结构合规，不替代完整 Build、INF/CAT、签名或实际加载验证；这些状态必须单独报告。`10.0.26100.0` 应替换为本机已安装的 WDK 版本。若链接前已经失败，修复原始编译/链接错误，而不是使用此后置校验路径。

驱动项目依赖 WDK。如果当前机器无法构建驱动，不要阻塞发行包制作；沿用统一 Release 目录中的已有未签名 R0 产物：`artifacts/bin\x64\Release\KswordARK.sys`、`artifacts/bin\x64\Release\KswordARK.pdb`、`artifacts/bin\x64\Release\KswordARKDriver.inf`。

## 2. 搭建发行目录

推荐从参考包提取完整 Qt 依赖与插件目录，再覆盖最新构建产物。这样能保持 `platforms`、`styles`、`imageformats`、`iconengines`、`generic`、`networkinformation`、`tls`、`translations`、`qtadvanceddocking.dll` 等布局一致。

```powershell
$ref=(Resolve-Path -LiteralPath $ReferenceArchive).Path # 明确选择的已验证旧包
$stageRoot=Join-Path (Get-Location) 'dist\KswordARK-release-work'
$stage=Join-Path $stageRoot 'Release'

if (Test-Path $stageRoot) { throw '暂存目录已存在；请先检查并选择新的目录。' }
New-Item -ItemType Directory -Path $stageRoot | Out-Null
tar -xf $ref -C $stageRoot

Copy-Item 'artifacts/bin\x64\Release\Ksword5.1.exe' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\Launcher.exe' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\KswordARKLight.exe' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\Taskbar.exe' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\KswordHUD.exe' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\APIMonitor_x64.dll' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\KswordDwmZOrder.dll' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\APIMonitor_x64.pdb' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\KswordARK.sys' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\KswordARK.pdb' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\KswordARKDriver.inf' $stage -Force
Copy-Item 'artifacts/bin\x64\Release\TaskmgrHijack.ps1' $stage -Force
Copy-Item 'LICENSE' (Join-Path $stage 'LICENSE') -Force
Copy-Item 'COMMUNITY_COVENANT.md' (Join-Path $stage 'COMMUNITY_COVENANT.md') -Force

$licenseDir=Join-Path $stage 'licenses\third_party'
New-Item -ItemType Directory -Path $licenseDir -Force | Out-Null
Copy-Item 'third_party\systeminformer_dyn\LICENSE.txt' (Join-Path $licenseDir 'systeminformer-LICENSE.txt') -Force
Copy-Item 'third_party\systeminformer_dyn\NOTICE.md' (Join-Path $licenseDir 'systeminformer-NOTICE.md') -Force
Copy-Item 'third_party\easy_hwid_spoofer\LICENSE.txt' (Join-Path $licenseDir 'easy-hwid-spoofer-LICENSE.txt') -Force
Copy-Item 'third_party\easy_hwid_spoofer\NOTICE.md' (Join-Path $licenseDir 'easy-hwid-spoofer-NOTICE.md') -Force
Copy-Item 'third_party\fltk\LICENSE.txt' (Join-Path $licenseDir 'fltk-LICENSE.txt') -Force
Copy-Item 'third_party\qt_advanced_docking_system\LICENSE.txt' (Join-Path $licenseDir 'qt-advanced-docking-system-LICENSE.txt') -Force
Copy-Item 'third_party\zstd\LICENSE.txt' (Join-Path $licenseDir 'zstd-LICENSE.txt') -Force

$profileDir=Join-Path $stage 'profiles'
if (!(Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir | Out-Null }
Copy-Item 'artifacts/bin\x64\Release\profiles\ark_dyndata_pack_v4.json.qz' $profileDir -Force
Copy-Item 'artifacts/bin\x64\Release\profiles\launcher_support_manifest.json' $profileDir -Force
Copy-Item 'artifacts/bin\x64\Release\profiles\registry_optimization_items.json.qz' $profileDir -Force
Copy-Item 'artifacts/bin\x64\Release\profiles\registry_optimization_assets' $profileDir -Recurse -Force

$languageDir=Join-Path $stage 'languages'
if (Test-Path $languageDir) { Remove-Item -LiteralPath $languageDir -Recurse -Force }
Copy-Item 'artifacts/bin\x64\Release\languages' $stage -Recurse -Force

$driverDir=Join-Path $stage 'KswordARKDriver'
if (!(Test-Path $driverDir)) { New-Item -ItemType Directory -Path $driverDir | Out-Null }
Copy-Item 'artifacts/bin\x64\Release\KswordARK.sys' $driverDir -Force
Copy-Item 'artifacts/bin\x64\Release\KswordARKDriver.inf' $driverDir -Force
```

## 3. 生成 7z 包

将 7-Zip 加入 PATH，或把 `$seven` 设为实际的 `7z.exe` 路径。压缩包放在 `dist/`，文件名包含日期与版本说明。

```powershell
$seven=(Get-Command 7z.exe -ErrorAction Stop).Source
$date=Get-Date -Format 'yyMMdd'
$archive=Join-Path (Get-Location) ("dist\KswordARK评估版本-$date-未签名R0-功能描述.7z")

if (Test-Path $archive) { throw '归档已存在；请选择新的文件名。' }
Push-Location 'dist\KswordARK-release-work'
& $seven a -t7z -mx=9 -mmt=on $archive 'Release'
$exit=$LASTEXITCODE
Pop-Location
if ($exit -ne 0) { exit $exit }
```

## 4. 校验发行包

生成后必须测试压缩包完整性，并列出关键文件确认最新 exe/dll/sys 已进入 `Release\`。

```powershell
$seven=(Get-Command 7z.exe -ErrorAction Stop).Source
& $seven t $archive
& $seven l $archive 'Release\Launcher.exe' 'Release\Ksword5.1.exe' 'Release\KswordARKLight.exe' 'Release\Taskbar.exe' 'Release\KswordHUD.exe' 'Release\APIMonitor_x64.dll' 'Release\KswordARK.sys' 'Release\drivers/ark\KswordARK.sys' 'Release\LICENSE' 'Release\COMMUNITY_COVENANT.md' 'Release\licenses\third_party\systeminformer-LICENSE.txt' 'Release\licenses\third_party\easy-hwid-spoofer-LICENSE.txt' 'Release\licenses\third_party\fltk-LICENSE.txt' 'Release\licenses\third_party\qt-advanced-docking-system-LICENSE.txt' 'Release\licenses\third_party\zstd-LICENSE.txt' 'Release\profiles\launcher_support_manifest.json' 'Release\profiles\ark_dyndata_pack_v4.json.qz' 'Release\profiles\registry_optimization_items.json.qz' 'Release\profiles\registry_optimization_assets\Config\Data.zip' 'Release\languages\zh-CN.json' 'Release\languages\en-US.json' 'Release\platforms\qwindows.dll'
```

校验通过时，`7z t` 输出应包含 `Everything is Ok`；另需确认主程序项目引用生成的 `Release\KswordDwmZOrder.dll` 已入包，窗口 DWM 排序功能从 exe 同目录加载该 DLL。主程序顶部“许可证”页面从 exe 同目录读取根 `LICENSE`。本流程生成的包根目录必须是 `Release\`，不要把 `dist\KswordARK-release-work\` 或其它临时目录打进包里。

比对暂存二进制和所选构建产物的 SHA256；归档完整性通过不能证明包里使用了最新文件。
同时核对随包的 notice、PDB、INF、运行时脚本，以及构建实际生成的压缩配置
`registry_optimization_items.json.qz`，不要回退复制已被构建步骤删除的未压缩 JSON。
