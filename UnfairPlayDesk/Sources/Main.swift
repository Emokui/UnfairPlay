import SwiftUI
import AppKit
import UniformTypeIdentifiers
import Darwin

typealias ViewState<Value> = SwiftUI.State<Value>

enum Page: String, CaseIterable, Identifiable {
    case account = "账户与模型", download = "下载 IPA", setup = "初始化模型", decrypt = "解密与验证"
    var id: String { rawValue }
    var icon: String { switch self { case .account: "person.crop.circle"; case .download: "arrow.down.circle"; case .setup: "key.horizontal"; case .decrypt: "lock.open" } }
}

struct ContentView: View {
    @StateObject var store = Store()
    @StateObject var runner = Runner()
    @ViewState var page: Page = .account
    @ViewState var profileName = ""
    @ViewState var newAppleID = ""
    @ViewState var showAddID = false
    @ViewState var showConsole = false
    @ViewState var appLink = ""
    @ViewState var appPath = ""
    @ViewState var setupIPA = ""
    @ViewState var inputIPA = ""
    @ViewState var reply = ""
    @ViewState var result: URL?
    @ViewState var operationAccount = ""
    @ViewState var alertText: String?
    @ViewState var accountToClear: Profile?
    @ViewState var accountToLogin: Profile?
    @ViewState var retryLoginID: UUID?
    @ViewState var showClearConfirmation = false
    @ViewState var accountToDeleteModel: Profile?
    @ViewState var showDeleteModelConfirmation = false
    @ViewState var accountToDelete: Profile?
    @ViewState var showDeleteAccountConfirmation = false
    var toolDir: URL { Bundle.main.resourceURL!.appendingPathComponent("Tools") }
    func tool(_ name: String) -> URL { toolDir.appendingPathComponent(name) }
    init(store: @autoclosure @escaping () -> Store = Store(), runner: @autoclosure @escaping () -> Runner = Runner(), initialPage: Page = .account) {
        _store = StateObject(wrappedValue: store())
        _runner = StateObject(wrappedValue: runner())
        _page = ViewState(wrappedValue: initialPage)
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(alignment: .leading, spacing: 24) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(page.rawValue).font(.system(size: 26, weight: .semibold))
                    Text(subtitle).font(.callout).foregroundStyle(.secondary)
                }
                modelPicker
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        switch page {
                        case .account: accountView
                        case .download: downloadView
                        case .setup: setupView
                        case .decrypt: decryptView
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 4)
                }.scrollIndicators(.hidden)
                activityView.background(ConsoleDismissMonitor { showConsole = false })
            }.padding(30).frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(nsColor: .windowBackgroundColor))
        }.frame(minWidth: 900, minHeight: 650)
        .onChange(of: runner.busy) { if runner.busy { showConsole = true } }
        .sheet(isPresented: $showAddID) {
            VStack(alignment: .leading, spacing: 18) {
                Text("添加新 ID").font(.title2.bold())
                Text("自动创建独立账户档案，并进入登录流程。").foregroundStyle(.secondary)
                TextField("Apple ID（邮箱或手机号）", text: $newAppleID).textFieldStyle(.roundedBorder)
                TextField("显示名称（可选，例如：日本 ID）", text: $profileName).textFieldStyle(.roundedBorder)
                Text("密码和验证码将在主窗口的隐藏输入框中输入。未设置显示名称时，使用 Apple ID 作为档案名称。").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("取消", role: .cancel) { showAddID = false; newAppleID = ""; profileName = "" }
                    Button("添加并登录", action: addAppleID).buttonStyle(.borderedProminent).tint(.teal)
                        .disabled(newAppleID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        .keyboardShortcut(.defaultAction)
                }
            }.padding(26).frame(width: 430)
        }
        .alert("提示", isPresented: Binding(get: { alertText != nil || store.error != nil }, set: { if !$0 { alertText = nil; store.error = nil; accountToLogin = nil } })) {
            if let account = accountToLogin {
                Button("重新登录") {
                    accountToLogin = nil
                    store.selected = account.id
                    runner.sensitive = true
                    run("ipatool", ["auth", "login"], "正在重新登录“\(account.name)”，请按下方提示输入", accountID: account.id)
                }
                Button("稍后", role: .cancel) { alertText = nil; accountToLogin = nil }
            } else {
                Button("好") { alertText = nil; store.error = nil }
            }
        } message: { Text(alertText ?? store.error ?? "") }
        .confirmationDialog("清除“\(accountToClear?.name ?? "")”的登录信息？", isPresented: $showClearConfirmation, titleVisibility: .visible) {
            Button("清除登录信息", role: .destructive) {
                if let account = accountToClear { clearLogin(account) }
                accountToClear = nil
            }
            Button("取消", role: .cancel) { accountToClear = nil }
        } message: {
            Text("清除这个档案保存的登录凭据和 Cookie。模型及其他账户保留；再次下载前需要重新登录。")
        }
        .confirmationDialog("删除“\(accountToDeleteModel?.name ?? "")”的当前模型？", isPresented: $showDeleteModelConfirmation, titleVisibility: .visible) {
            Button("删除模型", role: .destructive) {
                if let account = accountToDeleteModel { deleteModel(account) }
                accountToDeleteModel = nil
            }
            Button("取消", role: .cancel) { accountToDeleteModel = nil }
        } message: {
            Text("该账户档案内的所有已保存模型将移到废纸篓。账户档案、登录信息和其他账户的模型保留。之后需重新初始化或导入模型才能解密。")
        }
        .confirmationDialog("删除“\(accountToDelete?.name ?? "")”账户档案？", isPresented: $showDeleteAccountConfirmation, titleVisibility: .visible) {
            Button("删除此账户档案", role: .destructive) {
                if let account = accountToDelete { deleteAccount(account) }
                accountToDelete = nil
            }
            Button("取消", role: .cancel) { accountToDelete = nil }
        } message: {
            Text("将彻底删除此账户的登录凭据、会话目录、账户档案、模型目录和关联报告，不移入废纸篓，无法撤销。其他账户及已输出的 IPA 保留。")
        }
    }
    var sidebar: some View {
        VStack(alignment: .leading, spacing: 30) {
            HStack(spacing: 10) {
                if let image = DeskAppearance.icon {
                    Image(nsImage: image).resizable().frame(width: 38, height: 38)
                }
                Text("UnfairPlay").font(.system(size: 17, weight: .semibold))
            }.padding(.top, 20)
            VStack(spacing: 5) {
                ForEach(Page.allCases) { item in
                    Button { page = item } label: {
                        HStack(spacing: 11) {
                            Image(systemName: item.icon).font(.system(size: 15)).frame(width: 20)
                            Text(item.rawValue).font(.system(size: 13, weight: page == item ? .semibold : .regular))
                            Spacer(minLength: 0)
                        }.padding(.horizontal, 12).padding(.vertical, 11)
                            .foregroundStyle(page == item ? Color.teal : Color.primary.opacity(0.75))
                            .background(page == item ? Color.teal.opacity(0.1) : .clear, in: RoundedRectangle(cornerRadius: 9))
                            .contentShape(Rectangle())
                    }.buttonStyle(.plain)
                }
            }
            Spacer()
            HStack {
                Text("本机处理").font(.caption)
                Spacer()
                Text(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")
                    .font(.caption.monospacedDigit())
            }.foregroundStyle(.tertiary)
        }.padding(18).frame(width: 204).frame(maxHeight: .infinity).background(.bar)
    }
    var subtitle: String {
        switch page {
        case .account: "管理 Apple ID 与对应模型。"
        case .download: "下载应用，免费应用可自动获取许可。"
        case .setup: "使用已安装的 iPhone 或 iPad 应用创建模型。"
        case .decrypt: "使用当前账户的模型处理 IPA。"
        }
    }
    var modelPicker: some View {
        HStack(spacing: 14) {
            Image(systemName: "person.crop.circle").font(.system(size: 28, weight: .light)).foregroundStyle(.secondary)
            if store.profiles.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("尚未添加账户").font(.system(size: 13, weight: .medium))
                    Text("添加 Apple ID 后开始使用").font(.caption).foregroundStyle(.secondary)
                }
            } else {
                VStack(alignment: .leading, spacing: 3) {
                    Picker("当前账户", selection: $store.selected) {
                        ForEach(store.profiles) { Text($0.name).tag(Optional($0.id)) }
                    }.labelsHidden().fixedSize().accessibilityLabel("当前账户")
                    if let email = store.selectedProfile?.appleID {
                        Text(email).font(.caption).foregroundStyle(.secondary).lineLimit(1).textSelection(.enabled)
                    }
                }
            }
            Spacer(minLength: 8)
            Button { newAppleID = ""; profileName = ""; showAddID = true } label: {
                Image(systemName: "plus").font(.system(size: 13, weight: .medium)).frame(width: 24, height: 24)
            }.buttonStyle(.borderless).help("添加新 ID").accessibilityLabel("添加新 ID")
        }.padding(16).deskCard().disabled(runner.busy || !store.storageReady)
    }
    var accountView: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    Label("登录会话", systemImage: "person.badge.key").font(.headline)
                    Spacer()
                    Menu {
                        Button("清除此账户登陆", role: .destructive) {
                            accountToClear = store.selectedProfile; showClearConfirmation = accountToClear != nil
                        }
                        Button("删除此账户档案", role: .destructive) {
                            accountToDelete = store.selectedProfile; showDeleteAccountConfirmation = accountToDelete != nil
                        }
                    } label: { Image(systemName: "ellipsis").frame(width: 24, height: 20) }
                        .menuStyle(.borderlessButton).fixedSize().help("账户操作")
                }
                Text(store.selectedProfile?.deletionPending == true ? "删除尚未完成，请在账户菜单中继续删除。" : "切换账户即可复用已保存的登录会话。")
                    .font(.callout).foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    Button("查看登录状态") { run("ipatool", ["auth", "info"], "正在查看登录状态") }
                    if let account = store.selectedProfile, account.appleID == nil || retryLoginID == account.id {
                        Button("继续登录") { login(account) }
                    }
                }.disabled(!store.canUseSelected)
            }.padding(20).deskCard().disabled(store.selected == nil)
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    Label("账户模型", systemImage: "square.stack.3d.up").font(.headline)
                    Spacer()
                    Menu {
                        Button("打开模型目录") { if let url = store.profileURL { NSWorkspace.shared.open(url) } }
                        Button("重新校验模型") { store.refreshModel(force: true) }
                        Divider()
                        Button("删除当前模型", role: .destructive) {
                            accountToDeleteModel = store.selectedProfile; showDeleteModelConfirmation = accountToDeleteModel != nil
                        }
                    } label: { Image(systemName: "ellipsis").frame(width: 24, height: 20) }
                        .menuStyle(.borderlessButton).fixedSize().help("模型操作")
                }
                modelStatus
                HStack(spacing: 10) {
                    Button("导入模型…") { importModel() }
                    Button("初始化模型") { page = .setup }
                }
            }.padding(20).deskCard().disabled(!store.canUseSelected)
            if store.unresolvedReports > 0 {
                HStack {
                    Label("\(store.unresolvedReports) 份旧报告待确认归属", systemImage: "doc.text").foregroundStyle(.secondary)
                    Spacer()
                    Button("查看") { NSWorkspace.shared.open(store.root.appendingPathComponent("Reports")) }
                }.font(.caption)
            }
        }.disabled(runner.busy || !store.storageReady)
    }
    var modelStatus: some View {
        Label(store.modelMessage, systemImage: store.modelReady ? "checkmark.circle.fill" : "circle.dashed")
            .font(.callout).foregroundStyle(store.modelReady ? Color.teal : Color.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
    var downloadView: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 14) {
                Label("应用链接", systemImage: "link").font(.headline)
                TextField("粘贴 App Store 链接或数字 ID", text: $appLink)
                    .textFieldStyle(.roundedBorder).controlSize(.large)
                Text("下载地区由账户决定。免费应用会尝试自动获取许可；付费应用需先购买。")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(20).deskCard()
            Button(action: download) { Label("下载 IPA", systemImage: "arrow.down") }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(Core.appID(appLink) == nil || !store.canUseSelected)
            resultLink
        }.disabled(runner.busy)
    }
    var setupView: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("在 Mac App Store 登录对应 ID，安装并打开一次支持 Mac 的 iPhone / iPad 应用，再选择应用和匹配 IPA。")
                .font(.callout).foregroundStyle(.secondary)
            VStack(spacing: 0) {
                pathRow("已安装应用", path: appPath, label: "选择应用…", icon: "app") { chooseApp() }
                Divider().padding(.horizontal, 18)
                pathRow("匹配 IPA", path: setupIPA, label: "选择 IPA…") { chooseIPA { setupIPA = $0.path } }
            }.deskCard()
            Button("授权并初始化", action: setup).buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(!store.canUseSelected || appPath.isEmpty || setupIPA.isEmpty)
            Text("macOS 将请求管理员授权。已有模型会保留。")
                .font(.caption).foregroundStyle(.secondary)
        }.disabled(runner.busy)
    }
    var decryptView: some View {
        VStack(alignment: .leading, spacing: 20) {
            pathRow("加密 IPA", path: inputIPA, label: "选择 IPA…") { chooseIPA { inputIPA = $0.path } }.deskCard()
            modelStatus
            HStack(spacing: 12) {
                Button(action: decrypt) { Label("解密并保存", systemImage: "lock.open") }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                Button("仅验证") {
                    guard let model = store.profileURL else { return }
                    run("unfairplay", ["verify", "--input", inputIPA, "--model", model.path], "正在验证 IPA")
                }.controlSize(.large).help("验证 IPA，不保留解密内容")
            }.disabled(inputIPA.isEmpty || !store.modelReady || !store.canUseSelected)
            Text("也可将 IPA 拖入此页。安装前仍需签名。")
                .font(.caption).foregroundStyle(.secondary)
            resultLink
        }.disabled(runner.busy)
        .onDrop(of: [UTType.fileURL.identifier], isTargeted: nil) { providers in
            guard !runner.busy, let first = providers.first else { return false }
            _ = first.loadObject(ofClass: URL.self) { url, _ in
                if let url, url.pathExtension.lowercased() == "ipa" { DispatchQueue.main.async { inputIPA = url.path } }
            }
            return true
        }
    }
    @ViewBuilder var resultLink: some View {
        if let result {
            Button { NSWorkspace.shared.activateFileViewerSelecting([result]) } label: {
                Label(result.lastPathComponent, systemImage: "arrow.up.right.square")
                    .lineLimit(1).truncationMode(.middle)
            }.buttonStyle(.link).help("在 Finder 中显示")
        }
    }
    func pathRow(_ name: String, path: String, label: String, icon: String = "doc.zipper", action: @escaping ()->Void) -> some View {
        HStack(spacing: 14) {
            Image(systemName: icon).font(.system(size: 26, weight: .light)).foregroundStyle(.teal).frame(width: 34)
            VStack(alignment: .leading, spacing: 5) {
                Text(name).font(.system(size: 13, weight: .medium))
                Text(path.isEmpty ? "尚未选择" : URL(fileURLWithPath: path).lastPathComponent)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(path)
            }
            Spacer(minLength: 10)
            Button(label, action: action)
        }.padding(20)
    }
    var activityView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Divider()
            HStack(spacing: 10) {
                Button { showConsole.toggle() } label: {
                    HStack(spacing: 10) {
                        if runner.busy { ProgressView().controlSize(.small) }
                        else { Image(systemName: runner.hint == nil ? "circle.fill" : "exclamationmark.circle.fill").font(.system(size: 7)).foregroundStyle(runner.hint == nil ? Color.teal : Color.orange) }
                        Text(runner.title).font(.system(size: 12, weight: .medium)).lineLimit(1)
                        if !operationAccount.isEmpty { Text(operationAccount).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                        Spacer(minLength: 8)
                        Image(systemName: showConsole ? "chevron.down" : "chevron.up").frame(width: 20, height: 20)
                    }.frame(maxWidth: .infinity).contentShape(Rectangle())
                }.buttonStyle(.plain).help(showConsole ? "收起操作记录" : "展开操作记录").accessibilityLabel("操作记录")
                if runner.busy && !runner.privileged && !runner.saving { Button("取消") { runner.stop() }.controlSize(.small) }
            }
            if let hint = runner.hint { Text(hint).font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true) }
            if let progress = runner.progress, runner.busy { ProgressView(value: progress).tint(.teal) }
            if showConsole {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("操作记录").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("清空") { runner.log = ""; runner.currentLine = "" }.buttonStyle(.borderless).font(.caption).disabled(runner.busy)
                    }
                    ScrollViewReader { proxy in
                        ScrollView {
                            Text(runner.displayOutput).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            Color.clear.frame(height: 1).id("end")
                        }.frame(height: 108).onChange(of: runner.displayOutput) { proxy.scrollTo("end", anchor: .bottom) }
                    }
                }.padding(12).background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
            }
            if runner.canReply {
                HStack(spacing: 10) {
                    if runner.sensitive { SecureField("按提示输入密码、验证码或口令", text: $reply).onSubmit(sendReply) }
                    else { TextField("回复工具提示", text: $reply).onSubmit(sendReply) }
                    Toggle("隐藏", isOn: $runner.sensitive).toggleStyle(.checkbox)
                    Button("发送", action: sendReply).disabled(reply.isEmpty)
                }.textFieldStyle(.roundedBorder)
            }
        }
    }
    func sendReply() { runner.reply(reply); reply = "" }
    func addAppleID() {
        let email = newAppleID.trimmingCharacters(in: .whitespacesAndNewlines)
        let label = profileName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !email.isEmpty else { return }
        if let existing = store.profile(for: email) {
            store.selected = existing.id; showAddID = false
            if existing.appleID == nil { DispatchQueue.main.async { login(existing) } }
            else { alertText = "此 ID 已存在，已切换到原账户档案。" }
            return
        }
        guard let account = store.add(label.isEmpty ? email : label, requestedAppleID: email) else { showAddID = false; return }
        showAddID = false; profileName = ""; newAppleID = ""
        DispatchQueue.main.async { login(account) }
    }
    func login(_ account: Profile) {
        run("ipatool", ["auth", "login"], "正在登录“\(account.name)”，请按提示输入密码", accountID: account.id)
    }
    func run(_ name: String, _ args: [String], _ title: String, privileged: Bool = false, accountID: UUID? = nil, done: ((Bool)->Void)? = nil) {
        reply = ""
        operationAccount = store.profiles.first { $0.id == (accountID ?? store.selected) }?.name ?? ""
        guard name == "ipatool" else {
            guard store.canUseSelected else { alertText = "当前账户配置不可用或删除尚未完成。"; done?(false); return }
            runner.launch(tool(name), args, title: title, privileged: privileged, done: done); return
        }
        guard let id = accountID ?? store.selected, let account = store.profiles.first(where: { $0.id == id }), store.storageReady else {
            alertText = "账户配置不可用，请先修复配置或选择账户。"; done?(false); return
        }
        let revoke = args.starts(with: ["auth", "revoke"])
        guard account.deletionPending != true || revoke else { alertText = "此档案的删除尚未完成，请继续删除。"; done?(false); return }
        let prefix = ["--profile", id.uuidString, "--format", "json"]
        var arguments = args
        let login = args.starts(with: ["auth", "login"])
        let info = args.starts(with: ["auth", "info"])
        if login, let email = account.appleID ?? account.requestedAppleID {
            if let index = arguments.firstIndex(of: "--email"), index + 1 < arguments.count { arguments[index + 1] = email }
            else { arguments += ["--email", email] }
        }
        if login { retryLoginID = nil }
        let execute = {
            runner.launch(tool("ipatool"), prefix + arguments, title: title) { ok in
                guard ok else { if login || info { retryLoginID = id }; done?(false); return }
                if login || info {
                    do {
                        guard let email = Core.email(in: runner.output) else { throw DeskError("未能验证登录账户身份，请查看输出后重试。") }
                        try store.bindIdentity(id, email: email)
                    } catch {
                        alertText = error.localizedDescription; runner.title = "账户身份校验未通过"; done?(false); return
                    }
                }
                done?(true)
            }
        }
        if arguments.first == "download" {
            runner.launch(tool("ipatool"), prefix + ["auth", "info"], title: "正在核对下载账户") { ok in
                guard ok else { done?(false); return }
                do {
                    guard let email = Core.email(in: runner.output) else { throw DeskError("无法验证当前登录账户。") }
                    try store.bindIdentity(id, email: email)
                    execute()
                } catch { alertText = error.localizedDescription; runner.title = "账户身份不匹配"; done?(false) }
            }
        } else { execute() }
    }
    func clearLogin(_ account: Profile) {
        run("ipatool", ["auth", "revoke"], "正在清除“\(account.name)”的登录信息", accountID: account.id) { ok in
            guard ok else { return }
            let cookies = store.root.appendingPathComponent("Sessions/\(account.id.uuidString.lowercased())/cookies")
            do {
                if FileManager.default.fileExists(atPath: cookies.path) { try FileManager.default.removeItem(at: cookies) }
                runner.title = "“\(account.name)”的登录信息已清除"
                accountToLogin = account
                retryLoginID = account.id
                alertText = "“\(account.name)”的登录凭据和 Cookie 已清除，模型仍然保留。现在重新登录吗？"
            } catch {
                alertText = "登录凭据已清除，但 Cookie 清理失败：\(error.localizedDescription)"
            }
        }
    }
    func deleteModel(_ account: Profile) {
        guard !runner.busy, store.profiles.contains(where: { $0.id == account.id }) else { return }
        let directory = store.root.appendingPathComponent("Models/\(account.id.uuidString)")
        Task { @MainActor in
            let outcome = await runner.fileWork("正在删除模型…") { try Core.recycleModels(in: directory) }
            store.refreshModel(force: true)
            store.refreshLegacyCount()
            switch outcome {
            case .success(let removed):
                alertText = removed ? "“\(account.name)”的模型已移到废纸篓。登录信息仍然保留，可重新初始化或导入模型。" : "当前账户没有可删除的模型。"
            case .failure(let error): alertText = "删除模型失败：\(error.localizedDescription)"
            }
        }
    }
    func deleteAccount(_ account: Profile) {
        guard !runner.busy, store.profiles.contains(where: { $0.id == account.id }) else { return }
        run("ipatool", ["auth", "revoke"], "正在删除“\(account.name)”账户档案", accountID: account.id) { ok in
            guard ok else { return }
            Task { @MainActor in
                do {
                    try store.markDeleting(account.id)
                    let root = store.root
                    try await runner.fileWork("正在清理账户数据…") { try Core.removeAccountData(account.id, root: root) }.get()
                    try store.remove(account)
                    accountToLogin = nil
                    if retryLoginID == account.id { retryLoginID = nil }
                    reply = ""; runner.log = ""; runner.currentLine = ""; runner.output = ""; operationAccount = ""
                    runner.title = "“\(account.name)”账户档案已删除"
                    alertText = "“\(account.name)”的账户档案、登录信息、会话目录、模型目录和关联报告已彻底删除。"
                } catch {
                    store.objectWillChange.send()
                    alertText = "该账户的登录凭据已清除，但档案删除未完成：\(error.localizedDescription)\n部分数据可能已清理，请检查后重试。"
                }
            }
        }
    }
    func chooseIPA(_ done: (URL)->Void) {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .data]; panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { done(url) }
    }
    func chooseApp() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.applicationBundle]; panel.directoryURL = URL(fileURLWithPath: "/Applications"); panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { appPath = url.path }
    }
    func importModel() {
        guard let dest = store.profileURL, store.canUseSelected, let accountID = store.selected else { alertText = "请先选择可用账户。"; return }
        let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = false
        guard panel.runModal() == .OK, let source = panel.url else { return }
        let root = store.root
        Task { @MainActor in
            let prepared = await runner.fileWork("正在准备导入模型…") {
                let stage = try WorkStage.create(beside: root.appendingPathComponent("import.ipa"), root: root, accountID: accountID)
                do {
                    for file in try Core.modelFiles(source, requirePrivatePermissions: false) {
                        let target = stage.directory.appendingPathComponent(file.lastPathComponent)
                        try FileManager.default.copyItem(at: file, to: target)
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
                    }
                    return stage
                } catch { try? stage.cleanup(); throw error }
            }
            switch prepared {
            case .failure(let error): alertText = error.localizedDescription
            case .success(let stage):
                run("modelcheck", ["--model", stage.directory.path], "正在校验待导入模型") { ok in
                    let output = runner.output
                    let previousTitle = runner.title, previousHint = runner.hint
                    Task { @MainActor in
                        let eligible = store.selected == accountID && store.canUseSelected
                        let imported = await runner.fileWork("正在完成模型导入…") {
                            do {
                                if ok {
                                    guard eligible else { throw DeskError("账户已切换或不可修改，已取消导入。") }
                                    let json = try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [String: Any]
                                    guard (json?["checks"] as? [String: Any])?["model_valid"] as? Bool == true else { throw DeskError("模型完整性校验失败，未导入文件。") }
                                    try Core.installModels(stage.directory, to: dest)
                                }
                            } catch { try? stage.cleanup(); throw error }
                            try stage.cleanup()
                        }
                        store.refreshModel(force: true)
                        if !ok { runner.title = previousTitle; runner.hint = previousHint }
                        if case .failure(let error) = imported { alertText = error.localizedDescription }
                    }
                }
            }
        }
    }
    func download() {
        guard let id = Core.appID(appLink), store.canUseSelected else { return }
        let panel = NSSavePanel(); panel.nameFieldStringValue = "App-\(id).ipa"; panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .data]
        guard panel.runModal() == .OK, let target = panel.url else { return }
        do {
            let destination = try Core.OutputTarget(target)
            let stage = try WorkStage.create(beside: target, root: store.root, accountID: store.selected)
            run("ipatool", ["download", "--app-id", id, "--purchase", "--output", stage.ipa.path], "正在下载 IPA") { ok in
                Task { @MainActor in
                    defer { do { try stage.cleanup() } catch { alertText = "临时目录清理失败：\(error.localizedDescription)" } }
                    guard ok else { return }
                    if let saved = await saveCompletedIPA(stage.ipa, destination: destination) {
                        result = saved; inputIPA = saved.path; setupIPA = saved.path
                    }
                }
            }
        } catch { alertText = error.localizedDescription }
    }
    @MainActor func saveCompletedIPA(_ temporary: URL, destination: Core.OutputTarget, protecting input: URL? = nil) async -> URL? {
        var destination = destination
        while true {
            let chosen = destination
            let outcome = await runner.saveFile { try chosen.commit(temporary, protecting: input) }
            switch outcome {
            case .success: return chosen.url
            case .failure(let error):
                let alert = NSAlert()
                alert.messageText = "结果已完成，但未能保存"
                alert.informativeText = "\(error.localizedDescription)\n可选择其他位置，无需重新处理。"
                alert.addButton(withTitle: "另存为…")
                alert.addButton(withTitle: "放弃结果")
                guard alert.runModal() == .alertFirstButtonReturn else { return nil }
                let panel = NSSavePanel()
                panel.nameFieldStringValue = destination.url.lastPathComponent
                panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .data]
                if panel.runModal() == .OK, let url = panel.url {
                    do { destination = try Core.OutputTarget(url) }
                    catch { alertText = error.localizedDescription }
                }
            }
        }
    }
    func setup() {
        guard let model = store.profileURL, store.canUseSelected else { return }
        do { try Core.privateDirectory(model) } catch { alertText = error.localizedDescription; return }
        guard FileManager.default.fileExists(atPath: appPath), FileManager.default.fileExists(atPath: setupIPA) else { alertText = "选择的应用或 IPA 已不存在，请重新选择。"; return }
        run("authorize", ["setup", "--app", appPath, "--ipa", setupIPA, "--model-dir", model.path], "等待系统授权并初始化", privileged: true) { ok in
            store.refreshModel(force: true)
            if ok && !Core.hasModel(model) { alertText = "模型基本检查未通过，请查看模型状态。" }
        }
    }
    func decrypt() {
        guard let model = store.profileURL, let accountID = store.selected, store.modelReady, store.canUseSelected else { return }
        let input = URL(fileURLWithPath: inputIPA)
        let panel = NSSavePanel(); panel.nameFieldStringValue = input.deletingPathExtension().lastPathComponent + ".decrypted.ipa"; panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .data]
        guard panel.runModal() == .OK, let target = panel.url else { return }
        if Core.sameFile(input, target) { alertText = "输出位置与原始 IPA 实际上是同一个文件。"; return }
        do {
            let destination = try Core.OutputTarget(target)
            let reportDirectory = store.root.appendingPathComponent("Reports/\(accountID.uuidString)")
            try Core.privateDirectory(reportDirectory)
            let finalReport = reportDirectory.appendingPathComponent("\(UUID().uuidString).json")
            let stage = try WorkStage.create(beside: target, root: store.root, accountID: accountID)
            run("unfairplay", ["decrypt", "--input", input.path, "--model", model.path, "--output", stage.ipa.path, "--report", stage.report.path], "正在解密 IPA") { ok in
                Task { @MainActor in
                    defer { do { try stage.cleanup() } catch { alertText = "临时目录清理失败：\(error.localizedDescription)" } }
                    guard ok else { return }
                    if let saved = await saveCompletedIPA(stage.ipa, destination: destination, protecting: input) {
                        result = saved
                        do {
                            try Core.finalizeReport(stage.report, output: saved, accountID: accountID)
                            let json = try JSONSerialization.jsonObject(with: Data(contentsOf: stage.report))
                            try Core.writeJSON(json, to: finalReport)
                        } catch { alertText = "IPA 已成功保存，但报告保存失败：\(error.localizedDescription)" }
                    }
                }
            }
        } catch { alertText = error.localizedDescription }
    }

}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) { NSApp.setActivationPolicy(.regular); NSApp.activate(ignoringOtherApps: true) }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let active = Array(Runner.active.values)
        guard !active.isEmpty else { return .terminateNow }
        if active.allSatisfy(\.background) {
            active.forEach { $0.stop() }; waitForWorkers(); return .terminateLater
        }
        let alert = NSAlert()
        if active.contains(where: { $0.privileged || $0.saving }) {
            alert.messageText = "任务仍在运行"; alert.informativeText = "请等待初始化或文件处理完成后退出。"; alert.addButton(withTitle: "返回"); alert.runModal(); return .terminateCancel
        }
        alert.messageText = "任务仍在运行，是否取消后退出？"
        alert.informativeText = "软件会等待子任务停止并清理临时文件后退出。"
        alert.addButton(withTitle: "返回"); alert.addButton(withTitle: "取消任务并退出")
        guard alert.runModal() == .alertSecondButtonReturn else { return .terminateCancel }
        active.forEach { $0.stop() }
        waitForWorkers()
        return .terminateLater
    }
    func waitForWorkers() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            if Runner.active.isEmpty { NSApp.reply(toApplicationShouldTerminate: true) }
            else { self.waitForWorkers() }
        }
    }

}

#if !DESK_TESTING
struct UnfairPlayDeskApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    var body: some Scene {
        Window("UnfairPlay", id: "main") { ContentView().tint(.teal) }
            .windowStyle(.hiddenTitleBar).defaultSize(width: 1000, height: 740)
            .commands { CommandGroup(replacing: .newItem) {} }
    }
}
@main struct DeskMain {
    @MainActor static func main() {
        guard CommandLine.arguments.contains("--self-check") else { UnfairPlayDeskApp.main(); return }
        do {
            try Core.verifyBundle()
            let tools = Bundle.main.resourceURL!.appendingPathComponent("Tools")
            func check(_ name: String, args: [String], expected: Int32) throws -> String {
                let process = Process(); process.executableURL = tools.appendingPathComponent("worker")
                process.arguments = ["--parent", String(getpid()), tools.appendingPathComponent(name).path] + args
                let pipe = Pipe(); process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
                try process.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
                guard process.terminationStatus == expected else { throw DeskError("内置工具自检失败：\(name)") }
                return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            }
            let version = try check("ipatool", args: ["--version"], expected: 0)
            _ = try check("unfairplay", args: ["decrypt", "--help"], expected: 0)
            _ = try check("modelcheck", args: ["--help"], expected: 0)
            _ = try check("authorize", args: [], expected: 2)
            print("PASS: signed application resources, worker supervision, ipatool version \(version), decryption CLI, authorization argument rejection")
        } catch { fputs("\(error.localizedDescription)\n", stderr); exit(1) }
    }
}
#endif
