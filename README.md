<p align="center"><img src="AppIcon.png" width="112" alt="UnfairPlay icon"></p>
<h1 align="center">UnfairPlay</h1>
<p align="center">简洁的原生 macOS IPA 工作台</p>

## 下载与安装

从 [Releases](https://github.com/Emokui/UnfairPlay/releases/latest) 下载 **UnfairPlay-1.3.0.dmg**，打开后将 **UnfairPlay** 拖入 **Applications**。

- Apple 芯片 Mac，macOS **27.0 或更新版本**。
- 本版本为 ad-hoc 签名，未经过 Apple 开发者证书签名或公证。
- 不需要另外安装 Go。已有账户和模型可继续使用。

## 功能

- 独立 Apple ID 档案、登录会话与模型切换。
- 下载当前账户已获取许可的 App Store 应用。
- 初始化、导入、校验和删除账户模型。
- 本机 IPA 解密与验证，输出另存，支持拖放文件。
- 简洁侧栏、可折叠操作记录、系统浅色与深色外观。

账户及模型保存在 `~/Library/Application Support/UnfairPlayDesk/`。此处切换账户不会改变系统 Mac App Store 的登录账户。免费应用也需先用对应 ID 在 App Store 获取许可。

## 使用流程

1. 点击账户卡片右侧的 **＋**，添加 Apple ID 并按提示登录。
2. 在下载页输入 App Store 链接或数字 ID，下载已获取的 IPA。
3. 导入对应模型；或在初始化页选择已安装的兼容 iPhone/iPad 应用及匹配 IPA，按系统提示授权初始化。
4. 在解密页选择 IPA，解密并保存，或仅验证。安装前仍需签名。

账户和模型的管理操作在各自卡片右上角的 **…** 菜单中。

## 源码

[1.3.0 完整源码包](https://github.com/Emokui/UnfairPlay/releases/download/v1.3.0/UnfairPlay-1.3.0-source.zip) 包含 SwiftUI 界面、C 进程工具、测试、图标、构建脚本和修改后的 Go 依赖源码，不包含账户、模型或构建缓存。

解压后，在 `UnfairPlayDesk` 目录构建。需要 Xcode Command Line Tools 和 Go 1.25 或更新版本：

```sh
mkdir -p Tools
(cd Vendor/unfairplay && go build -o ../../Tools/unfairplay ./cmd/unfairplay)
chmod +x build.sh test.sh package-dmg.sh
./build.sh ./Tools
./test.sh
./package-dmg.sh
```

模型校验器使用与已验证引擎一致的上游版本 `41f064bfe0ef947e748b785b8ab62697a64bdbe6`。源码包内 README 包含实现、验证记录与限制说明。

## 致谢与许可

- [DrWhax/unfairplay](https://github.com/DrWhax/unfairplay)：核心模型与 IPA 处理工具。
- [majd/ipatool](https://github.com/majd/ipatool)：App Store 下载与账户操作。

第三方许可证和声明保留在源码包的 `Licenses/` 与对应 `Vendor/` 目录，以及应用包的 `Contents/Resources/Licenses/` 中。
