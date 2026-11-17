<p align="center"><img src="UnfairPlayDesk/Assets/AppIcon.png" width="112" alt="UnfairPlay 图标"></p>
<h1 align="center">UnfairPlay</h1>
<p align="center">原生 macOS IPA 工作台</p>

## 下载与安装

从 [GitHub Releases](https://github.com/Emokui/UnfairPlay/releases) 下载已发布版本的 DMG。打开镜像后，将 **UnfairPlay.app** 拖入 **Applications**。安装包内置所需工具，使用时无需安装 Go。

当前源码版本为 **1.5.7**，面向 Apple 芯片 Mac，最低部署目标为 macOS 14.0。系统版本和模型支持范围见[兼容性说明](UnfairPlayDesk/COMPATIBILITY.md)。

## 功能

- 搜索 App Store 应用，切换地区，浏览历史版本并下载当前账户有许可的 IPA。
- 分别管理各 Apple 账户的登录会话、商店地区和模型。
- 批量选择本机 IPA，查看加密状态，解密或验证所选文件。
- 管理默认下载目录，在 Finder 中定位 IPA 或通过 AirDrop 发送。

## 从源码构建

需要 Xcode Command Line Tools 和 Go 1.26.5 或更新版本。下载或克隆仓库后运行：

```sh
cd UnfairPlayDesk
./build.sh
./test.sh
./package-dmg.sh
```

`build.sh` 在仓库根目录生成 `UnfairPlay.app`，`package-dmg.sh` 在同处生成版本化的 DMG。默认构建使用 ad-hoc 签名。构建参数及 Go 测试命令见[项目说明](UnfairPlayDesk/README.md#编译与测试)。

SwiftUI 界面和 C 辅助工具在 [Sources](UnfairPlayDesk/Sources/)，回归代码在 [Tests](UnfairPlayDesk/Tests/)，随项目编译的 Go 源码在 [Vendor](UnfairPlayDesk/Vendor/)。

## 致谢与许可

IPA 处理工具来自 [DrWhax/unfairplay](https://github.com/DrWhax/unfairplay)，账户与下载工具基于 [majd/ipatool](https://github.com/majd/ipatool)。第三方许可及声明见 [Licenses](UnfairPlayDesk/Licenses/) 和各 Vendor 目录。
