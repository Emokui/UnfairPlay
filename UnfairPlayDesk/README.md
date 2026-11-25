# UnfairPlay 1.5.8

UnfairPlay 是面向 Apple 芯片 Mac 的 App Store 应用搜索、IPA 下载与本地处理工具。最低部署目标为 macOS 14.0。

[更新日志](CHANGELOG.md) · [兼容性与验证范围](COMPATIBILITY.md) · [第三方许可](Licenses/)

## 使用

退出旧版本后，从「应用程序」打开 UnfairPlay。升级时沿用已有账户档案与模型。

- **添加新 ID**：输入 Apple ID 和可选名称，自动创建独立档案并进入登录。需要密码或验证码时，使用弹窗输入。登录成功后保存返回的真实 Apple ID；重新登录会使用绑定身份，下载前也会核对身份。重复或不匹配的身份会被拒绝。
- **查看状态**：账户菜单显示本地登录状态。会话已保存表示本地存在加密会话文件；旧版升级后尚未触发迁移的账户会提示待首次使用时迁移，令牌有效性由实际账户操作确认。
- **切换账户**：选择账户档案即可复用对应会话。不同 UUID 的钥匙串项目、Cookie 和模型独立；不会替你切换系统 Mac App Store。
- **搜索与下载**：搜索应用或粘贴 App Store 链接、数字 ID，选择版本与保存位置。缺少许可时自动尝试免费获取；付费应用需先用同一 ID 购买。`license is required` 表示当前 ID 仍未取得许可，界面会给出中文处理建议。
- **初始化模型**：先在 Mac App Store 登录相应账户，安装并打开一个支持 Mac 的 iPhone/iPad 应用，再选择该应用和对应账户下载的匹配 IPA。管理员授权由 macOS 提示。系统构建是否受支持由内置工具校验，不能强行跳过。
- **导入与校验模型**：导入内容先复制到私有临时目录，经内置解析器完整校验后才接收。同名模型原子替换。已有模型在后台校验并缓存结果，切换账户或刷新时通过文件元数据识别外部修改；也可手动重新校验。校验状态包括权限、格式、版本及完整性，目录里有 `.bin` 不代表已可用于解密。
- **解密与验证**：选择模型和 IPA，可拖入 IPA。解密输出原子保存，报告记录最终输出路径和账户 UUID。
- **清除此账户登陆**：确认后只清除当前档案的凭据、缓存与 Cookie，保留模型。完成提示中可选择重新登录。
- **删除当前模型**：确认后将当前档案的模型移到废纸篓。删除前会先迁移可明确归属的旧报告，避免以后删除账户时漏掉报告。
- **删除此账户档案**：先清除凭据，成功后保存“删除未完成”状态，再清理会话、模型目录、报告及关联临时任务，最后移除档案。清除凭据失败或取消时，尚未进入删除状态的账户仍可使用。不移到废纸篓。失败会保留档案入口供检查和重试。其他账户、用户另存的 IPA 和导入源文件不自动删除。

## 数据与安全

数据位于 `~/Library/Application Support/UnfairPlayDesk/`：

- `profiles.json`：账户名称、UUID、已确认的 Apple ID、待删除状态；权限 600。
- `Models/<UUID>/`：私有模型；目录权限 700、文件权限 600。
- `Sessions/<UUID>/`：独立 Cookie、AES-256-GCM 加密会话及进程锁；目录权限 700。系统钥匙串保存该账户的 `session-master-v1` 主密钥。已配置的文件凭据后端仍可保存主密钥并按需请求口令。
- `Reports/<UUID>/`：该账户的解密报告，包含账户 UUID 和实际输出路径。
- `Jobs/`：临时任务恢复记录。

旧版共享报告在模型仍可读取时，通过模型实际内容摘要建立归属；不依据文件名猜测。无法明确区分归属的旧资料会保留，界面会显示数量和目录入口，不会误删其他账户。

下载与解密在输出位置旁创建私有临时目录，工作进程使用 umask 077。提交前会检查真实路径和文件标识，拒绝覆盖原 IPA，包括符号链接与硬链接；最终文件权限固定为 600，不继承旧输出的宽松权限。

普通任务退出时会先停止子任务、清理临时文件，再关闭程序。初始化运行时要求等待完成；异常退出后监管进程会终止遗留子任务，下一次启动清理已登记的临时目录。单窗口和数据目录锁可避免多实例覆盖账户配置。配置损坏或不可读时会禁止写入；保存时还会检查配置是否被外部修改。

管理员调用仅允许固定 `setup --app … --ipa … --model-dir …` 参数组合，模型目标必须是当前用户的私有 UUID 目录。系统自带启动器以清空的环境启动授权桥接，把固定的 root-helper 和 UnfairPlay 复制到 root 私有临时目录，校验固定 SHA-256 和代码签名后执行。执行结果使用真实退出状态，不用输出中的 success 字样判断。管理员密码不由本应用保存，不安装常驻服务。

默认构建为本机 ad-hoc 签名版本，未使用 Apple 开发者证书公证。每次运行应用时首次启动工具前检查应用资源完整性；第三方代码与许可见应用包 `Contents/Resources/Licenses`。

## 编译与测试

需要 Apple 芯片 Mac、Xcode Command Line Tools、Python 3 与 Go 1.26.5 或更新版本。Go 默认读取 `build/go-runtime/go/bin/go` 或 PATH，也可通过 `DESK_GO_BINARY` 指定。默认从 `Vendor/unfairplay` 的固定版本源码编译引擎与模型校验器，不依赖旧的 `unfairplay-tools` 目录。也可用 `./build.sh /path/to/tools` 指定现有引擎目录；不会放宽其解密校验逻辑。

```sh
./build.sh
./test.sh
./package-dmg.sh
```

如有可用的开发者签名证书，可用 `DESK_SIGNING_IDENTITY="证书名称或 SHA-1" ./build.sh` 统一签名主程序及内置工具。证书需已在本机钥匙串中；仅设置变量不会自动申请证书或完成公证。

Go 测试（在 `Vendor/ipatool` 运行）：

```sh
go test -count=1 ./cmd ./pkg/keychain ./pkg/http ./pkg/appstore ./internal/cachelock ./internal/store ./internal/store/emulator ./internal/store/profile ./internal/storeauth ./internal/sap/assets ./internal/sap/machimage ./internal/sap/machine ./internal/sap/unicorn
```

软件包只读自检：

```sh
"../UnfairPlay.app/Contents/MacOS/UnfairPlayDesk" --self-check
```
