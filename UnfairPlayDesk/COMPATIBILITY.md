# UnfairPlay 1.5.7 兼容性与验证范围

面向 Apple 芯片 Mac，目标系统为 macOS 14、15、26、27。最低安装版本为 14.0，Swift、C、Go/cgo 均按 macOS 14.0 部署目标编译。最低部署目标只说明构建要求，不能代替各系统实机验证。

| 系统 | 部署目标覆盖 | 1.5.7 实机功能验证 |
| --- | --- | --- |
| macOS 14 | 是 | 待实机验证 |
| macOS 15 | 是 | 待实机验证 |
| macOS 26 | 是 | 待实机验证 |
| macOS 27 | 是 | 待实机验证 |

## 本版交付范围

- 编译 Swift 界面、C 授权与进程辅助工具、Go 下载器及原有解密引擎，执行构建必要的代码签名验证。
- Apple 账户登录、IPA 下载和模型初始化应在目标系统上实测。
- 登录与下载使用 ipatool 2.8.0 桌面分支，并合入 v2.8.1 的组件缓存、Mach-O 解析共享、Unicorn JIT 缓冲及 Apple 登录对话响应处理；内置版本标识为 `2.8.0-desk.7`。
- 账户 UUID、会话与模型格式保留，缓存 v5 兼容读取旧 v4 组件并转换。首次冷准备仍需要 Apple 网络资源，有阶段日志和超时，不保证固定完成时间。
- 模型初始化取决于系统 FairPlay 数据与布局；macOS 部署目标不表示所有系统构建都支持初始化。原有解密结构与完整性校验保留。
- 默认 ad-hoc 签名未公证，更新工具后二进制身份可能变化并触发钥匙串授权；构建可通过 `DESK_SIGNING_IDENTITY` 使用本机现有证书，没有降低钥匙串保护。

## 界面与目录

界面采用浅色外观，提供账户与模型、搜索与下载、解密与验证三个页面。下载期间可继续切换页面、搜索应用、浏览版本和选择文件，冲突任务及账户修改继续限制。取消底部日志；需要输入时弹出密码、验证码或解锁口令窗口，任务运行时标题右侧显示进度。已下载 IPA 入口在搜索框右侧。左下角账户卡片与独立加号保留，账户列表固定向上展开。

搜索地区按已确认的账户商店匹配，缺失或不在选项中时默认美国，仍可手动选择。搜索不需要登录；下载需要已绑定账户。

历史版本来源为 Timbrd、Bilin、iOSDump，已移除 Agzy。公开索引只接收 App ID，不接收账户密码；IPA 从 Apple 下载。Bilin 先前曾返回 HTTP 403，本版没有复测各来源可用性，也不把一次失败视为永久失效。版本记录可能缺失或过期，是否可下载以 Apple 响应及账户许可为准。

## 参考

- [ipadn 公共目录搜索](https://github.com/mengangs/ipadn/blob/main/iPadn-iOS/iPadn/Services/StoreService.swift)：名称、ID、链接入口，公开目录与账户下载分开。
- [Pastel 目录和版本记录](https://github.com/EEliberto/Pastel-macOS/blob/main/NodeProject/src/catalog.js)：公开版本索引、external version ID、从 Apple 下载指定版本。
- [ipatool v2.8.1](https://github.com/majd/ipatool/releases/tag/v2.8.1)：本次选取的上游组件与运行时优化；桌面分支另有本地修复，未声称整仓升级为原版 v2.8.1。
- [unfairplay](https://github.com/DrWhax/unfairplay)：继续使用现有初始化与解密引擎；它不负责 Apple 账户登录和 IPA 下载。
