# UnfairPlay 1.5.8 兼容性与验证范围

应用面向 Apple 芯片 Mac，Swift、C 和 Go/cgo 的最低部署目标均为 macOS 14.0。模型初始化还取决于当前 macOS 构建的 FairPlay 数据布局。

| 系统 | 部署目标覆盖 | 1.5.8 实机功能验证 |
| --- | --- | --- |
| macOS 14 | 是 | 待验证 |
| macOS 15 | 是 | 待验证 |
| macOS 26 | 是 | 待验证 |
| macOS 27 | 是 | 待验证 |

## 运行条件

- 应用搜索使用公开目录。下载需要对应地区的 Apple 账户和应用许可，历史版本是否可下载以 Apple 响应为准。
- 首次登录可能需要从网络准备 Apple 认证组件和 Unicorn 运行库。后续运行可复用本机缓存。
- 升级沿用原账户档案和模型。旧版凭据在首次需要凭据时迁移，钥匙串可能提示授权。默认构建使用 ad-hoc 签名，跨版本更新后 macOS 可能再次要求授权。
- 应用生成的账户、会话、模型及报告保存在本机用户目录。目录和编译说明见 [项目文档](README.md)。

## 构建验证

构建脚本会校验应用及内嵌工具的代码签名。打包脚本会检查安装镜像的完整性。回归测试可通过 `./test.sh` 单独执行。在线登录、IPA 下载、模型初始化和界面交互需在目标系统上验证。

## 参考

- [ipadn 公共目录搜索](https://github.com/mengangs/ipadn/blob/main/iPadn-iOS/iPadn/Services/StoreService.swift)：名称、ID、链接入口，公开目录与账户下载分开。
- [Pastel 目录和版本记录](https://github.com/EEliberto/Pastel-macOS/blob/main/NodeProject/src/catalog.js)：公开版本索引、external version ID、从 Apple 下载指定版本。
- [ipatool v2.8.1](https://github.com/majd/ipatool/releases/tag/v2.8.1)：本次选取的上游组件与运行时优化；桌面分支另有本地修复，未声称整仓升级为原版 v2.8.1。
- [unfairplay](https://github.com/DrWhax/unfairplay)：继续使用现有初始化与解密引擎；它不负责 Apple 账户登录和 IPA 下载。
