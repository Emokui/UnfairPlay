import SwiftUI
import AppKit
import UniformTypeIdentifiers
import Darwin

typealias ViewState<Value> = SwiftUI.State<Value>

enum Page: String, CaseIterable, Identifiable {
    case account = "账户与模型", download = "搜索与下载", decrypt = "解密与验证"
    var id: String { rawValue }
    var icon: String { switch self { case .account: "person.crop.circle"; case .download: "arrow.down.circle"; case .decrypt: "lock.open" } }
}

private struct ModelSetupSelection {
    var appPath = ""
    var ipaPath = ""
}

struct OperationNotice: Identifiable {
    let id = UUID()
    let title: String
    let detail: String?
    let symbol: String
}

struct ContentView: View {
    @StateObject var store = Store()
    @StateObject var runner = Runner()
    @StateObject var catalog = DownloadCatalog()
    @StateObject var updates = UpdateChecker()
    @AppStorage("deskAppearance") var appearance = "system"
    @Environment(\.colorScheme) private var systemColorScheme
    @ViewState var showUpdateDetails = false
    @ViewState var page: Page = .account
    @ViewState var profileName = ""
    @ViewState var newAppleID = ""
    @ViewState var showAddID = false
    @ViewState var showAccountMenu = false
    @ViewState var pendingLogin: Profile?
    @ViewState var showDownloads = false
    @ViewState var downloadedIPAs = DownloadedIPA.load()
    @AppStorage("fallbackIPADownloadDirectory") var downloadDirectoryPath = ""
    @ViewState var ipaFolderRevision = 0
    @ViewState var appLink = ""
    @ViewState var catalogQuery = ""
    @ViewState var submittedCatalogQuery = ""
    @ViewState var showAppDetails = false
    @ViewState var purchasePageAppID: String?
    @ViewState var showModelSetup = false
    @ViewState var showVersionEntry = false
    @ViewState var preventAppStoreUpdates = false
    @ViewState private var setupSelections: [UUID: ModelSetupSelection] = [:]
    @ViewState var inputIPAs: [URL] = []
    @ViewState var manuallyAddedIPAs: [URL] = (UserDefaults.standard.stringArray(forKey: "importedIPAPaths") ?? []).map { URL(fileURLWithPath: $0).standardizedFileURL }
    @AppStorage("saveIPAsDirectly") var saveIPAsDirectly = false
    @ViewState var selectedReport: IPASavedReport?
    @ViewState var showOperationDetails = false
    @ViewState var ipaStatuses: [URL: IPAStatusEntry] = [:]
    @ViewState var recentIPAOutputs: [URL] = []
    @ViewState var ipaBatchPosition: String?
    @ViewState var operationAccount = ""
    @ViewState var alertText: String?
    @ViewState var completionNotice: OperationNotice?
    @FocusState private var addIDFocused: Bool
    @ViewState var accountToClear: Profile?
    @ViewState var accountToLogin: Profile?
    @ViewState var appStoreAcquisitionURL: URL?
    @ViewState var accountsNeedingLogin = Set<UUID>()
    @ViewState var showClearConfirmation = false
    @ViewState var accountToDeleteModel: Profile?
    @ViewState var showDeleteModelConfirmation = false
    @ViewState var accountToDelete: Profile?
    @ViewState var showDeleteAccountConfirmation = false
    var needsSelectedLogin: Bool { store.selected.map(accountsNeedingLogin.contains) ?? false }
    var canDownload: Bool {
        store.canUseSelected && store.selectedProfile?.appleID != nil &&
            store.selectedProfile?.loginCleared != true && !needsSelectedLogin
    }
    var appPath: String {
        get { store.selected.flatMap { setupSelections[$0]?.appPath } ?? "" }
        nonmutating set {
            if let account = store.selected { setupSelections[account, default: ModelSetupSelection()].appPath = newValue }
        }
    }
    var setupIPA: String {
        get { store.selected.flatMap { setupSelections[$0]?.ipaPath } ?? "" }
        nonmutating set {
            if let account = store.selected { setupSelections[account, default: ModelSetupSelection()].ipaPath = newValue }
        }
    }
    var decryptableIPAs: [URL] { inputIPAs.filter { ipaStatuses[$0]?.status != .clear } }
    var toolDir: URL { Bundle.main.resourceURL!.appendingPathComponent("Tools") }
    func tool(_ name: String) -> URL { toolDir.appendingPathComponent(name) }
    init(store: @autoclosure @escaping () -> Store = Store(), runner: @autoclosure @escaping () -> Runner = Runner(), initialPage: Page = .account) {
        _store = StateObject(wrappedValue: store())
        _runner = StateObject(wrappedValue: runner())
        _page = ViewState(wrappedValue: initialPage)
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar.zIndex(1)
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .center, spacing: 16) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(page.rawValue).font(.system(size: 23, weight: .semibold))
                        Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 0)
                    if runner.busy {
                        operationIndicator
                            .help("查看阶段耗时与操作详情")
                            .popover(isPresented: $showOperationDetails) {
                                TimelineView(.periodic(from: .now, by: 1)) { _ in
                                    VStack(alignment: .leading, spacing: 12) {
                                        Text("操作详情").font(.system(size: 13, weight: .semibold))
                                        ScrollView {
                                            Text(runner.diagnosticReport(detail: runner.hint ?? ""))
                                                .font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                        }
                                    }.padding(18).frame(width: 520, height: 360)
                                }
                            }
                    }
                    else if let completionNotice { operationCompletion(completionNotice) }
                }.frame(maxWidth: DeskAppearance.contentWidth).frame(maxWidth: .infinity)
                    .padding(.horizontal, 32).padding(.top, 26).padding(.bottom, 22)
                Group {
                    switch page {
                    case .download:
                        downloadView
                    case .decrypt:
                        decryptView
                    case .account:
                        ScrollView {
                            accountView.frame(maxWidth: DeskAppearance.contentWidth, alignment: .leading).frame(maxWidth: .infinity)
                                .padding(.bottom, 24)
                        }.scrollIndicators(.hidden)
                    }
                }.padding(.horizontal, 32).frame(maxWidth: .infinity, maxHeight: .infinity)
            }.frame(maxWidth: .infinity, maxHeight: .infinity).background(DeskAppearance.background)
        }.frame(minWidth: 900, minHeight: 650).font(.system(size: 12)).tint(DeskAppearance.accent)
        .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
        .task { await updates.check() }
        .onAppear { DeskAppearance.apply(appearance); refreshIPAReferences() }
        .onChange(of: appearance) { DeskAppearance.apply(appearance) }
        .onChange(of: page) { refreshIPAReferences() }
        .onChange(of: manuallyAddedIPAs) { UserDefaults.standard.set(manuallyAddedIPAs.map(\.path), forKey: "importedIPAPaths") }
        .sheet(item: $selectedReport) { IPAReportView(report: $0) }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            refreshIPAReferences()
            if page == .decrypt { ipaFolderRevision += 1 }
        }
        .onChange(of: runner.busy) {
            if !runner.busy { showOperationDetails = false }
            if runner.busy { showAccountMenu = false }
            else {
                if store.selectedProfile?.storeFront == nil { syncAccountRegion() }
            }
        }
        .onChange(of: runner.canReply) {
            if runner.canReply { showDownloads = false; selectedReport = nil; showOperationDetails = false }
        }
        .onChange(of: store.selected) {
            completionNotice = nil
            showAccountMenu = false
            showModelSetup = false
            showVersionEntry = false
            purchasePageAppID = nil
            refreshIPAReferences()
            catalog.changeAccount()
            let previousCountry = catalog.country
            syncAccountRegion()
            if page == .download && previousCountry == catalog.country { resumeCatalog() }
        }
        .onChange(of: catalog.country) { if page == .download { resumeCatalog() } }
        .onChange(of: store.selectedProfile?.storeFront) { syncAccountRegion() }
        .onChange(of: canDownload) { syncAccountRegion() }
        .sheet(isPresented: $showAddID, onDismiss: {
            if let account = pendingLogin {
                pendingLogin = nil
                login(account)
            }
        }) {
            VStack(spacing: 12) {
                DeskSheetHeader(symbol: "person.crop.circle.badge.plus", title: "添加新 ID",
                                message: "为这个 Apple ID 创建独立的账户档案。")
                VStack(spacing: 8) {
                    TextField("Apple ID（邮箱或手机号）", text: $newAppleID).focused($addIDFocused)
                    TextField("显示名称（可选）", text: $profileName)
                }.textFieldStyle(.roundedBorder).controlSize(.large).padding(.vertical, 5)
                HStack(spacing: 10) {
                    Spacer()
                    Button("取消", role: .cancel) { showAddID = false; newAppleID = ""; profileName = "" }
                        .keyboardShortcut(.cancelAction)
                    Button("添加并登录", action: addAppleID).buttonStyle(DeskPrimaryButtonStyle(compact: true))
                        .disabled(newAppleID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        .keyboardShortcut(.defaultAction)
                }
            }.padding(24).frame(width: 380).onAppear { addIDFocused = true }
        }
        .sheet(isPresented: Binding(get: { runner.canReply && !showAddID && selectedReport == nil }, set: { presented in
            if !presented && runner.canReply { runner.stop() }
        })) {
            if let prompt = runner.inputPrompt {
                CredentialSheet(prompt: prompt, account: operationAccount, submit: runner.reply, cancel: runner.stop)
                    .id(prompt).interactiveDismissDisabled()
            }
        }
        .alert("提示", isPresented: Binding(get: { alertText != nil || store.error != nil }, set: { if !$0 {
            alertText = nil; store.error = nil; accountToLogin = nil; appStoreAcquisitionURL = nil
        } }), presenting: alertText ?? store.error) { detail in
            if let url = appStoreAcquisitionURL {
                Button("在 App Store 获取") { NSWorkspace.shared.open(url) }
                Button("好", role: .cancel) { alertText = nil }
            } else if let account = accountToLogin {
                Button("重新登录") {
                    accountToLogin = nil
                    store.selected = account.id
                    run("ipatool", ["auth", "login"], "正在重新登录“\(account.name)”", accountID: account.id)
                }
                Button("稍后", role: .cancel) { alertText = nil; accountToLogin = nil }
            } else {
                Button("好") { alertText = nil; store.error = nil }
            }
            Button("导出诊断…") { DispatchQueue.main.async { exportDiagnostic(detail) } }
            Button("复制详情") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(detail, forType: .string)
            }
        } message: { detail in Text(detail) }
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
        VStack(alignment: .leading, spacing: 32) {
            VStack(alignment: .leading, spacing: 6) {
                Text("UnfairPlay").font(.system(size: 18, weight: .semibold, design: .rounded))
                Text("IPA WORKSPACE").font(.system(size: 9, weight: .medium)).tracking(2).foregroundStyle(.secondary)
            }.padding(.horizontal, 10).padding(.top, 28)
            VStack(spacing: 8) {
                ForEach(Page.allCases) { item in
                    Button { page = item } label: {
                        HStack(spacing: 12) {
                            Image(systemName: item.icon).font(.system(size: 15, weight: .medium)).frame(width: 20)
                            Text(item.rawValue).font(.system(size: 12, weight: page == item ? .semibold : .regular))
                            Spacer(minLength: 0)
                        }.padding(.horizontal, 13).padding(.vertical, 13)
                            .foregroundStyle(page == item ? Color.white : Color.primary.opacity(0.65))
                            .background(page == item ? DeskAppearance.activeFill : .clear, in: RoundedRectangle(cornerRadius: 11))
                            .contentShape(Rectangle())
                    }.buttonStyle(.plain)
                }
            }
            Spacer()
            accountSwitcher.padding(.bottom, 16)
            HStack {
                Button {
                    let dark = appearance == "dark" || (appearance == "system" && systemColorScheme == .dark)
                    appearance = dark ? "light" : "dark"
                } label: {
                    Image(systemName: isDarkAppearance ? "sun.max" : "moon")
                        .font(.system(size: 12)).frame(width: 22, height: 22).contentShape(Rectangle())
                }.buttonStyle(.plain).foregroundStyle(.secondary)
                    .help(isDarkAppearance ? "切换至浅色模式" : "切换至深色模式")
                    .accessibilityLabel(isDarkAppearance ? "切换至浅色模式" : "切换至深色模式")
                Spacer(minLength: 4)
                Button {
                    showUpdateDetails = true
                    Task { await updates.check(manual: true) }
                } label: {
                    HStack(spacing: 4) {
                        if updates.available != nil { Image(systemName: "arrow.up.circle.fill") }
                        Text(updates.available.map { "更新 \($0)" } ?? UpdateChecker.currentVersion).lineLimit(1)
                    }
                }.buttonStyle(.plain)
                    .foregroundStyle(updates.available == nil ? Color.secondary : DeskAppearance.accent)
                    .help(updates.available.map { "发现新版本 \($0)，点击查看" } ?? "检查更新")
                    .popover(isPresented: $showUpdateDetails, arrowEdge: .top) {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("软件更新").font(.system(size: 13, weight: .semibold))
                            if updates.checking {
                                ProgressView("正在检查更新…").controlSize(.small)
                            } else if let version = updates.available {
                                Text("新版本 \(version) 已发布。").font(.system(size: 12))
                                Button("查看更新") { NSWorkspace.shared.open(UpdateChecker.releaseURL); showUpdateDetails = false }
                                    .buttonStyle(DeskPrimaryButtonStyle(compact: true))
                            } else {
                                Text(updates.message ?? "当前已是最新版本。").font(.system(size: 12)).foregroundStyle(.secondary)
                            }
                        }.padding(18).frame(width: 230, alignment: .leading)
                    }
            }.font(.system(size: 10)).foregroundStyle(.tertiary).padding(.horizontal, 8)
        }.padding(16).frame(width: 188).frame(maxHeight: .infinity).background(DeskAppearance.sidebar)
    }
    var isDarkAppearance: Bool {
        appearance == "dark" || (appearance == "system" && systemColorScheme == .dark)
    }
    var accountSwitcher: some View {
        HStack(spacing: 8) {
            Button { showAccountMenu.toggle() } label: {
                HStack(spacing: 8) {
                    Image(systemName: "person.crop.circle.fill")
                        .resizable().scaledToFit().frame(width: 28, height: 28)
                        .foregroundStyle(DeskAppearance.accent.opacity(0.8))
                    Text(store.selectedProfile?.name ?? "暂无账户")
                        .font(.system(size: 11, weight: .medium)).foregroundStyle(.primary)
                        .lineLimit(1).truncationMode(.tail).frame(maxWidth: .infinity, alignment: .leading)
                    Image(systemName: "chevron.up").font(.system(size: 9, weight: .medium)).foregroundStyle(.secondary)
                }.contentShape(Rectangle())
            }.buttonStyle(.plain).disabled(store.profiles.isEmpty)
                .help("切换账户").accessibilityLabel("切换账户")
            Button { showAccountMenu = false; newAppleID = ""; profileName = ""; showAddID = true } label: {
                Image(systemName: "plus").font(.system(size: 12, weight: .medium))
                    .frame(width: 24, height: 28)
                    .background(DeskAppearance.accent.opacity(0.07), in: RoundedRectangle(cornerRadius: 7))
            }.buttonStyle(.plain).foregroundStyle(DeskAppearance.accent)
                .help("添加账户").accessibilityLabel("添加账户")
        }.padding(8).background(DeskAppearance.surface.opacity(0.8), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.primary.opacity(0.035), lineWidth: 1))
            .disabled(runner.busy || !store.storageReady)
            .overlay(alignment: .bottomLeading) {
                if showAccountMenu {
                    accountMenuContents
                        .background(DeskAppearance.surface, in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.primary.opacity(0.06), lineWidth: 1))
                        .shadow(color: .black.opacity(0.1), radius: 12, y: 4)
                        .padding(.bottom, 52)
                        .background(OutsideClickMonitor { showAccountMenu = false })
                        .onExitCommand { showAccountMenu = false }
                }
            }.zIndex(1)
    }
    var accountMenuContents: some View {
        let font = NSFont.systemFont(ofSize: 12)
        let nameWidth = store.profiles.map { ($0.name as NSString).size(withAttributes: [.font: font]).width }.max() ?? 0
        return ScrollView {
            VStack(spacing: 0) {
                ForEach(store.profiles) { profile in
                    Button {
                        showAccountMenu = false
                        store.selected = profile.id
                    } label: {
                        HStack {
                            Text(profile.name).font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            if store.selected == profile.id {
                                Image(systemName: "checkmark").font(.system(size: 10, weight: .medium)).foregroundStyle(DeskAppearance.accent)
                            }
                        }.padding(.horizontal, 8).frame(maxWidth: .infinity).frame(height: 32)
                            .background(store.selected == profile.id ? DeskAppearance.accent.opacity(0.07) : .clear, in: RoundedRectangle(cornerRadius: 6))
                            .contentShape(Rectangle())
                    }.buttonStyle(.plain).help(profile.name)
                }
            }
        }.frame(height: min(CGFloat(store.profiles.count) * 32, 192)).scrollIndicators(.hidden)
            .padding(4).frame(width: min(224, max(118, ceil(nameWidth) + 48))).disabled(runner.busy || !store.storageReady)
    }
    var subtitle: String {
        switch page {
        case .account: "管理 Apple ID 与对应模型。"
        case .download: "查找应用，选择版本，保存到本机。"
        case .decrypt: "使用当前账户的模型处理 IPA。"
        }
    }
    var accountView: some View {
        VStack(alignment: .leading, spacing: 20) {
            if store.profiles.isEmpty {
                DeskEmptyState(symbol: "person.crop.circle.badge.plus", title: "从一个 Apple ID 开始", message: "独立保存登录会话与模型，随时切换账户。")
                    .frame(height: 230)
                Button("添加 Apple ID") { newAppleID = ""; profileName = ""; showAddID = true }
                    .buttonStyle(DeskPrimaryButtonStyle(compact: true)).frame(maxWidth: .infinity).disabled(runner.busy)
            } else {
                VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 13) {
                    Image(systemName: "person.crop.circle").font(.system(size: 34, weight: .ultraLight)).foregroundStyle(DeskAppearance.accent)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(store.selectedProfile?.name ?? "账户").font(.system(size: 16, weight: .medium)).textSelection(.enabled)
                        if let profile = store.selectedProfile {
                            let identity = profile.appleID ?? profile.requestedAppleID
                            if let identity, identity != profile.name {
                                Text(identity).font(.system(size: 11)).foregroundStyle(.secondary).textSelection(.enabled)
                            }
                            HStack(spacing: 9) {
                                Label(accountStatus(profile), systemImage: canDownload ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(needsSelectedLogin ? Color.orange : (canDownload ? DeskAppearance.accent : Color.secondary))
                                if let region = StorefrontRegions.country(forStoreFront: profile.storeFront) {
                                    Label(StorefrontRegions.name(for: region), systemImage: "globe").foregroundStyle(.secondary)
                                        .help("账户商店地区")
                                }
                            }.font(.caption)
                        }
                    }
                    Spacer()
                    Menu {
                        Button("查看状态") { showLocalSessionStatus() }
                            .disabled(!store.canUseSelected)
                        if let account = store.selectedProfile, account.appleID == nil || account.loginCleared == true || accountsNeedingLogin.contains(account.id) {
                            Button("继续登录") { login(account) }.disabled(!store.canUseSelected)
                        }
                        Divider()
                        Button("清除此账户登陆", role: .destructive) { accountToClear = store.selectedProfile; showClearConfirmation = accountToClear != nil }
                            .disabled(!store.canUseSelected || store.selectedProfile?.loginCleared == true ||
                                      (store.selectedProfile?.appleID == nil && !needsSelectedLogin))
                        Button("删除此账户档案", role: .destructive) { accountToDelete = store.selectedProfile; showDeleteAccountConfirmation = accountToDelete != nil }
                    } label: { Image(systemName: "ellipsis").frame(width: 20, height: 20) }
                        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize().help("账户操作").accessibilityLabel("账户操作").disabled(runner.busy)
                }
                    Divider()
                if store.selectedProfile?.deletionPending == true {
                    Text("此档案删除未完成，请从账户菜单继续删除。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        Label("账户模型", systemImage: "square.stack.3d.up")
                            .font(.system(size: 12, weight: .medium))
                        Spacer()
                        Menu {
                            Button("打开模型目录") { if let url = store.profileURL { NSWorkspace.shared.open(url) } }
                            Button("重新校验模型") { store.refreshModel(force: true) }.disabled(runner.busy)
                            Divider()
                            Button("删除当前模型", role: .destructive) { accountToDeleteModel = store.selectedProfile; showDeleteModelConfirmation = accountToDeleteModel != nil }
                                .disabled(runner.busy || !store.canUseSelected)
                        } label: { Image(systemName: "ellipsis").frame(width: 20, height: 20) }
                            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize().help("模型操作")
                    }
                    modelStatus
                    HStack(spacing: 10) {
                        Button("导入模型…", action: importModel).controlSize(.small).disabled(runner.busy)
                        Spacer()
                        Button {
                            withAnimation(.easeInOut(duration: 0.16)) { showModelSetup.toggle() }
                        } label: {
                            HStack(spacing: 6) {
                                Text(showModelSetup ? "收起初始化" : "初始化模型")
                                Image(systemName: showModelSetup ? "chevron.up" : "chevron.down").font(.system(size: 9, weight: .medium))
                            }.font(.system(size: 11))
                        }.buttonStyle(.borderless)
                    }.disabled(!store.canUseSelected)
                    if showModelSetup {
                        Divider()
                        modelSetupView
                    }
                }
                }.padding(20).deskCard(cornerRadius: 16)
                if store.unresolvedReports > 0 {
                    HStack {
                        Text("\(store.unresolvedReports) 份旧报告待确认归属").foregroundStyle(.secondary)
                        Spacer()
                        Button("查看报告") { NSWorkspace.shared.open(store.root.appendingPathComponent("Reports")) }
                    }.font(.caption)
                }
            }
        }.disabled(!store.storageReady)
    }
    private func accountStatus(_ profile: Profile) -> String {
        if profile.deletionPending == true { return "待完成删除" }
        if profile.loginCleared == true { return "登录已清除" }
        if profile.appleID == nil { return "未登录" }
        return accountsNeedingLogin.contains(profile.id) ? "需要重新登录" : "已登录"
    }
    var modelStatus: some View {
        Label(store.modelMessage, systemImage: store.modelReady ? "checkmark.circle.fill" : "circle.dashed")
            .font(.system(size: 12)).foregroundStyle(store.modelReady ? DeskAppearance.accent : Color.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
    var modelSetupView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("先在 Mac App Store 登录对应 ID，安装并打开兼容的 iPhone / iPad 应用，再选择应用与匹配 IPA。")
                .font(.system(size: 11)).foregroundStyle(.secondary).lineSpacing(3)
            VStack(spacing: 0) {
                pathRow("已安装应用", path: appPath, label: "选择应用", icon: "app") { chooseApp() }
                Divider().padding(.horizontal, 12)
                pathRow("匹配 IPA", path: setupIPA, label: "选择 IPA") { chooseIPA { setupIPA = $0.path } }
            }.background(DeskAppearance.background, in: RoundedRectangle(cornerRadius: 10))
            HStack(spacing: 12) {
                Text("需要管理员授权，已有模型会保留。")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
                Button("授权并初始化", action: setup).buttonStyle(DeskPrimaryButtonStyle(compact: true))
                    .disabled(runner.busy || !store.canUseSelected || appPath.isEmpty || setupIPA.isEmpty)
            }
        }
    }
    private var ipaLibraryFiles: [URL] { recentIPAOutputs + manuallyAddedIPAs + downloadedIPAs.map(\.url) }
    var decryptView: some View {
        let folder = defaultDownloadFolder.standardizedFileURL
        return VStack(alignment: .leading, spacing: 18) {
            IPAFolderList(
                folder: folder,
                revision: ipaFolderRevision,
                selection: $inputIPAs,
                additionalFiles: ipaLibraryFiles,
                statuses: Binding(get: { ipaStatuses }, set: { entries in
                    if folder == defaultDownloadFolder.standardizedFileURL { ipaStatuses = entries }
                }),
                profiles: store.profiles,
                selectedAccount: store.selected,
                modelSelectors: store.modelSelectors,
                modelCheckStates: store.modelCheckStates,
                downloads: downloadedIPAs,
                canSwitchAccount: !runner.busy && store.storageReady,
                switchAccount: { store.selected = $0 },
                viewReport: showIPAReport,
                changeFolder: { chooseDefaultDownloadFolder() },
                browse: addIPAsFromPicker
            )
            HStack {
                Toggle("直接保存到默认文件夹", isOn: $saveIPAsDirectly).toggleStyle(.checkbox).font(.system(size: 11))
                    .help(defaultDownloadFolder.path).disabled(runner.busy)
                Spacer()
                Button("查看解密报告") { if let file = inputIPAs.first { showIPAReport(file) } }.controlSize(.small)
                    .disabled(inputIPAs.count != 1)
            }
            HStack {
                Text("当前模型").font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
                modelStatus
            }
            HStack(spacing: 14) {
                Group {
                    Button { processSelectedIPAs(verifyOnly: false) } label: {
                        Label("解密并保存", systemImage: "lock.open")
                    }.buttonStyle(DeskPrimaryButtonStyle()).controlSize(.large)
                        .disabled(decryptableIPAs.isEmpty)
                        .help("使用当前账户的模型解密")
                    Button("仅验证") { processSelectedIPAs(verifyOnly: true) }
                        .controlSize(.large).help("验证所选 IPA")
                }.disabled(runner.busy || inputIPAs.isEmpty || !store.modelReady || !store.canUseSelected)
                if inputIPAs.count > decryptableIPAs.count {
                    let skipped = inputIPAs.count - decryptableIPAs.count
                    Text("\(skipped) 份 IPA 无需解密").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("移到废纸篓…", role: .destructive, action: trashSelectedIPAs)
                    .disabled(runner.busy || inputIPAs.isEmpty)
                    .help("将选中的 IPA 移到废纸篓")
            }
        }
        .padding(.bottom, 24)
        .frame(maxWidth: DeskAppearance.contentWidth, maxHeight: .infinity, alignment: .topLeading)
        .frame(maxWidth: .infinity)
        .task(id: store.profiles.map(\.id)) { store.refreshAllModels() }
        .onChange(of: ipaFolderRevision) { store.refreshAllModels() }
        .onDrop(of: [UTType.fileURL.identifier], isTargeted: nil) { providers in
            let files = providers.filter { $0.canLoadObject(ofClass: URL.self) }
            for provider in files {
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    if let url { DispatchQueue.main.async { addInputIPAs([url]) } }
                }
            }
            return !files.isEmpty
        }
    }
    func refreshIPAReferences() {
        let folder = defaultDownloadFolder.standardizedFileURL
        let referenced = Set((ipaLibraryFiles + inputIPAs).map(\.standardizedFileURL))
        let cached = ipaStatuses.filter { file, _ in
            (file.deletingLastPathComponent() == folder || referenced.contains(file)) && !Core.isMissingFile(file)
        }
        if cached.count != ipaStatuses.count { ipaStatuses = cached }
        let existing = downloadedIPAs.filter { !Core.isMissingFile($0.url) }
        if existing.count != downloadedIPAs.count {
            downloadedIPAs = existing
            DownloadedIPA.save(existing)
        }
        if !setupIPA.isEmpty, Core.isMissingFile(URL(fileURLWithPath: setupIPA)) { setupIPA = "" }
        let remainingInputs = inputIPAs.filter { !Core.isMissingFile($0) }
        if remainingInputs.count != inputIPAs.count { inputIPAs = remainingInputs }
        let remainingAdded = manuallyAddedIPAs.filter { !Core.isMissingFile($0) }
        if remainingAdded.count != manuallyAddedIPAs.count { manuallyAddedIPAs = remainingAdded }
        let remainingOutputs = recentIPAOutputs.filter { !Core.isMissingFile($0) }
        if remainingOutputs.count != recentIPAOutputs.count { recentIPAOutputs = remainingOutputs }
    }
    func pathRow(_ name: String, path: String, label: String, icon: String = "doc.zipper", action: @escaping ()->Void) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 18, weight: .light)).foregroundStyle(DeskAppearance.accent).frame(width: 24)
            VStack(alignment: .leading, spacing: 4) {
                Text(name).font(.system(size: 11, weight: .medium))
                Text(path.isEmpty ? "尚未选择" : URL(fileURLWithPath: path).lastPathComponent)
                    .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(path)
            }
            Spacer(minLength: 10)
            Button(label, action: action).controlSize(.small)
        }.padding(12)
    }
    var operationIndicator: some View {
        HStack(spacing: 10) {
            VStack(alignment: .trailing, spacing: 6) {
                HStack(spacing: 8) {
                    Text(runner.title).lineLimit(1).help(runner.title)
                    if let ipaBatchPosition { Text(ipaBatchPosition).monospacedDigit() }
                    if let progress = runner.progress {
                        Text(progress, format: .percent.precision(.fractionLength(0))).monospacedDigit()
                    }
                }
                ProgressView(value: runner.progress)
                    .progressViewStyle(.linear).controlSize(.small)
                    .frame(width: 142).accessibilityLabel("任务进度")
            }.contentShape(Rectangle()).onTapGesture { showOperationDetails.toggle() }
            if !runner.privileged && !runner.saving {
                Button(action: runner.stop) { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).help("取消任务").accessibilityLabel("取消任务")
            }
        }.font(.system(size: 11)).foregroundStyle(.secondary).frame(maxWidth: 320, alignment: .trailing)
    }
    func showCompletion(_ title: String, detail: String? = nil, duration: TimeInterval = 5, symbol: String = "checkmark.circle.fill") {
        let notice = OperationNotice(title: title, detail: detail, symbol: symbol)
        completionNotice = notice
        DispatchQueue.main.asyncAfter(deadline: .now() + duration) {
            if completionNotice?.id == notice.id { completionNotice = nil }
        }
    }
    private func operationCompletion(_ notice: OperationNotice) -> some View {
        HStack(spacing: 8) {
            Image(systemName: notice.symbol).foregroundStyle(DeskAppearance.accent)
                .accessibilityHidden(true)
            VStack(alignment: .trailing, spacing: 3) {
                Text(notice.title).font(.system(size: 11, weight: .medium))
                if let detail = notice.detail {
                    Text(detail).font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle).help(detail)
                }
            }
        }.frame(maxWidth: 320, alignment: .trailing)
    }
    func exportDiagnostic(_ detail: String) {
        let report = runner.diagnosticReport(detail: detail)
        let panel = NSSavePanel()
        panel.title = "导出诊断"
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "UnfairPlay-diagnostic.txt"
        panel.directoryURL = defaultDownloadFolder
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        do {
            try Data(report.utf8).write(to: destination, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        } catch {
            alertText = "诊断导出失败：\(error.localizedDescription)"
        }
    }
    func showOperationFailure(_ title: String) {
        guard !runner.cancelled else { return }
        alertText = Core.operationError(title: title, hint: runner.hint, output: runner.output)
    }
    func addAppleID() {
        let email = newAppleID.trimmingCharacters(in: .whitespacesAndNewlines)
        let label = profileName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !email.isEmpty else { return }
        if let existing = store.profile(for: email) {
            store.selected = existing.id
            if existing.appleID == nil || existing.loginCleared == true || accountsNeedingLogin.contains(existing.id) { pendingLogin = existing }
            else { alertText = "此 ID 已存在，已切换到原账户档案。" }
            showAddID = false; newAppleID = ""; profileName = ""
            return
        }
        guard let account = store.add(label.isEmpty ? email : label, requestedAppleID: email) else { showAddID = false; return }
        pendingLogin = account
        showAddID = false; profileName = ""; newAppleID = ""
    }
    private func showLocalSessionStatus() {
        guard let account = store.selectedProfile else { return }
        let url = store.root.appendingPathComponent("Sessions/\(account.id.uuidString.lowercased())/session-v1.enc")
        let message: String
        do {
            if !canDownload { message = accountStatus(account) }
            else if let stamp = try Core.fileStamp(url) {
                message = stamp.mode & S_IFMT == S_IFREG && stamp.size > 0 ? "本地会话已保存" : "本地会话文件异常"
            } else { message = "未找到本地会话文件" }
        } catch { message = "无法读取本地会话状态" }
        showCompletion(message, detail: account.appleID ?? account.requestedAppleID ?? account.name, duration: 2, symbol: "info.circle")
    }
    func login(_ account: Profile) {
        run("ipatool", ["auth", "login"], "正在登录“\(account.name)”", accountID: account.id)
    }
    func run(_ name: String, _ args: [String], _ title: String, privileged: Bool = false, accountID: UUID? = nil, holdsCompletion: Bool = false, done: ((Bool)->Void)? = nil) {
        operationAccount = store.profiles.first { $0.id == (accountID ?? store.selected) }?.name ?? ""
        guard name == "ipatool" else {
            guard store.canUseSelected else { alertText = "当前账户配置不可用或删除尚未完成。"; done?(false); return }
            runner.launch(tool(name), args, title: title, privileged: privileged, holdsCompletion: holdsCompletion) { ok in
                if !ok { showOperationFailure(title) }
                done?(ok)
            }
            return
        }
        guard let id = accountID ?? store.selected, let account = store.profiles.first(where: { $0.id == id }), store.storageReady else {
            alertText = "账户配置不可用，请先修复配置或选择账户。"; done?(false); return
        }
        let revoke = args.starts(with: ["auth", "revoke"])
        guard account.deletionPending != true || revoke else { alertText = "此档案的删除尚未完成，请继续删除。"; done?(false); return }
        let prefix = ["--profile", id.uuidString, "--format", "json"]
        var arguments = args
        let login = args.starts(with: ["auth", "login"])
        if login, let email = account.appleID ?? account.requestedAppleID {
            if let index = arguments.firstIndex(of: "--email"), index + 1 < arguments.count { arguments[index + 1] = email }
            else { arguments += ["--email", email] }
        }
        if (arguments.first == "download" || arguments.first == "get-version-metadata"), let email = account.appleID { arguments += ["--expected-account", email] }
        if revoke { SessionKeyChannel.forget(id) }
        runner.launch(tool("ipatool"), prefix + arguments, title: title, holdsCompletion: holdsCompletion, sessionAccount: id) { ok in
            guard ok else {
                let error = runner.output.lowercased()
                if error.contains("encrypted account session failed authentication") { SessionKeyChannel.forget(id) }
                let licenseRejected = error.contains("free app license rejected after sign-in refresh")
                let missingSession = Core.isMissingSession(in: error)
                let needsLogin = missingSession || (!licenseRejected && (error.contains("auth code is required") ||
                    error.contains("password token is expired") || error.contains("failed to refresh apple login") ||
                    error.contains("store amd state is not provisioned") || error.contains("returned no store amd proof") ||
                    error.contains("session expired") || error.contains("account session was cleared") ||
                    error.contains("download account does not match") || error.contains("account does not match selected profile")))
                if !runner.cancelled && needsLogin {
                    accountsNeedingLogin.insert(id)
                }
                if !runner.cancelled {
                    do {
                        if try store.bindRefreshedSession(id, in: runner.output) {
                            if !needsLogin { accountsNeedingLogin.remove(id) }
                            if store.selected == id { syncAccountRegion() }
                        }
                    } catch {
                        alertText = error.localizedDescription; runner.title = "账户身份校验未通过"; done?(false); return
                    }
                }
                if args.first != "get-version-metadata" {
                    if !runner.cancelled && args.first == "download" && needsLogin { accountToLogin = account }
                    showOperationFailure(title)
                }
                done?(false); return
            }
            if login {
                do {
                    guard let email = Core.email(in: runner.output) else { throw DeskError("未能验证登录账户身份，请查看输出后重试。") }
                    try store.bindIdentity(id, email: email, storeFront: Core.storeFront(in: runner.output))
                    accountsNeedingLogin.remove(id)
                    if store.selected == id {
                        catalog.updateAccountCountry(store.selectedProfile?.storeFront, afterLogin: true)
                        catalog.purchaseStatus = [:]
                        showCompletion("登录成功", detail: email)
                    }
                } catch {
                    alertText = error.localizedDescription; runner.title = "账户身份校验未通过"; done?(false); return
                }
            } else if let email = Core.email(in: runner.output) {
                do {
                    try store.bindIdentity(id, email: email, storeFront: Core.storeFront(in: runner.output))
                    accountsNeedingLogin.remove(id)
                    if store.selected == id { syncAccountRegion() }
                } catch {
                    alertText = error.localizedDescription; runner.title = "账户身份校验未通过"; done?(false); return
                }
            }
            done?(true)
        }
    }
    func clearLogin(_ account: Profile) {
        run("ipatool", ["auth", "revoke"], "正在清除“\(account.name)”的登录信息", accountID: account.id) { ok in
            guard ok else { return }
            let cookies = store.root.appendingPathComponent("Sessions/\(account.id.uuidString.lowercased())/cookies")
            do {
                try store.markLoginCleared(account.id)
                syncAccountRegion()
                if FileManager.default.fileExists(atPath: cookies.path) { try FileManager.default.removeItem(at: cookies) }
                runner.title = "“\(account.name)”的登录信息已清除"
                accountToLogin = account
                accountsNeedingLogin.remove(account.id)
                alertText = "“\(account.name)”的登录凭据和 Cookie 已清除，模型仍然保留。现在重新登录吗？"
            } catch {
                alertText = "登录凭据已清除，但 Cookie 清理失败：\(error.localizedDescription)"
            }
        }
    }
    func deleteModel(_ account: Profile) {
        guard !runner.busy, store.profiles.contains(where: { $0.id == account.id && $0.deletionPending != true }) else { return }
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
        run("ipatool", ["auth", "revoke"], "正在删除“\(account.name)”账户档案", accountID: account.id, holdsCompletion: true) { ok in
            Task { @MainActor in
                defer { runner.finishCompletion() }
                guard ok else { return }
                do {
                    try store.markDeleting(account.id)
                    let root = store.root
                    try await runner.fileWork("正在清理账户数据…") { try Core.removeAccountData(account.id, root: root) }.get()
                    try store.remove(account)
                    for index in downloadedIPAs.indices where downloadedIPAs[index].accountID == account.id {
                        downloadedIPAs[index].accountID = nil
                    }
                    DownloadedIPA.save(downloadedIPAs)
                    accountToLogin = nil
                    accountsNeedingLogin.remove(account.id)
                    setupSelections.removeValue(forKey: account.id)
                    runner.log = ""; runner.currentLine = ""; runner.output = ""; operationAccount = ""
                    runner.title = "“\(account.name)”账户档案已删除"
                    alertText = "“\(account.name)”的账户档案、登录信息、会话目录、模型目录和关联报告已彻底删除。"
                } catch {
                    store.objectWillChange.send()
                    alertText = "该账户的登录凭据已清除，但档案删除未完成：\(error.localizedDescription)\n部分数据可能已清理，请检查后重试。"
                }
            }
        }
    }
    func chooseIPA(in folder: URL? = nil, _ done: (URL)->Void) {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .data]; panel.canChooseDirectories = false
        panel.directoryURL = folder
        if panel.runModal() == .OK, let url = panel.url { done(url) }
    }
    func chooseApp() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.applicationBundle]; panel.directoryURL = URL(fileURLWithPath: "/Applications"); panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { appPath = url.path }
    }
    func importModel() {
        guard !runner.busy else { return }
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
                run("modelcheck", ["--model", stage.directory.path], "正在校验待导入模型", holdsCompletion: true) { ok in
                    let output = runner.output
                    let previousTitle = runner.title, previousHint = runner.hint
                    Task { @MainActor in
                        defer { runner.finishCompletion() }
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
                        switch imported {
                        case .success:
                            if ok { showCompletion("模型已导入") }
                        case .failure(let error): alertText = error.localizedDescription
                        }
                    }
                }
            }
        }
    }
    var defaultDownloadFolder: URL {
        if !downloadDirectoryPath.isEmpty {
            return URL(fileURLWithPath: downloadDirectoryPath, isDirectory: true)
        }
        return FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads", isDirectory: true)
    }
    @discardableResult
    func chooseDefaultDownloadFolder(message: String = "选择保存 IPA 的默认文件夹。") -> URL? {
        let picker = NSOpenPanel()
        picker.canChooseDirectories = true
        picker.canChooseFiles = false
        picker.canCreateDirectories = true
        picker.directoryURL = defaultDownloadFolder
        picker.message = message
        picker.prompt = "设为默认"
        guard picker.runModal() == .OK, let folder = picker.url else { return nil }
        downloadDirectoryPath = folder.path
        refreshIPAReferences()
        ipaFolderRevision += 1
        return folder
    }
    func downloadDirectory() -> URL? {
        let folder = defaultDownloadFolder
        var isDirectory = ObjCBool(false)
        if FileManager.default.fileExists(atPath: folder.path, isDirectory: &isDirectory), isDirectory.boolValue {
            return folder
        }
        return chooseDefaultDownloadFolder(message: "当前默认下载文件夹不可用，请选择新的默认文件夹。")
    }
    func download() {
        guard !runner.busy, let id = Core.appID(appLink), canDownload, catalog.validVersion,
              !catalog.isWaitingForAppName(id), let folder = downloadDirectory(), let accountID = store.selected else { return }
        let app = catalog.app(for: id)
        let appName = app?.name ?? "应用"
        let paid = app?.priceText != nil
        let noUpdate = preventAppStoreUpdates
        let direct = saveIPAsDirectly
        let selectedVersion = catalog.selectedVersion
        let knownVersion = selectedVersion.isEmpty ? app?.version : (catalog.details[selectedVersion]?.displayVersion ?? catalog.versions.first { $0.id == selectedVersion }?.version)
        let suggestedVersion = DownloadedIPA.versionForFilename(knownVersion, versionID: selectedVersion)
        let filename = DownloadedIPA.filename(for: appName, noUpdate: noUpdate, version: suggestedVersion)
        do {
            let destination: Core.OutputTarget
            if direct {
                destination = try DownloadedIPA.unusedTarget(named: filename, in: folder)
            } else {
                let panel = NSSavePanel()
                panel.directoryURL = folder
                panel.nameFieldStringValue = filename
                panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .data]
                guard panel.runModal() == .OK, let target = panel.url else { return }
                destination = try Core.OutputTarget(target)
            }
            let stage = try WorkStage.create(beside: destination.url, root: store.root, accountID: accountID)
            let acquisition = paid ? [] : ["--purchase"]
            let updateOptions = noUpdate ? ["--no-update"] : []
            let arguments = ["download", "--app-id", id, "--output", stage.ipa.path] + acquisition + updateOptions + catalog.versionArguments
            completionNotice = nil
            run("ipatool", arguments, "正在下载 IPA", holdsCompletion: true) { ok in
                if !ok && !runner.cancelled && runner.title != "账户身份校验未通过" {
                    let error = runner.output.lowercased()
                    if paid && error.contains("license is required") {
                        catalog.purchaseStatus[id] = .unowned
                    } else if !paid && (error.contains("license is required") || error.contains("free app license rejected after sign-in refresh")) {
                        let accountRegion = DownloadCatalog.country(forStoreFront: store.profiles.first { $0.id == accountID }?.storeFront)
                        appStoreAcquisitionURL = URL(string: "https://apps.apple.com/\(accountRegion.lowercased())/app/id\(id)")
                    }
                }
                Task { @MainActor in
                    defer {
                        do { try stage.cleanup() }
                        catch {
                            accountToLogin = nil
                            appStoreAcquisitionURL = nil
                            alertText = "临时目录清理失败：\(error.localizedDescription)"
                        }
                        runner.finishCompletion()
                    }
                    guard ok else { return }
                    runner.recordStage("正在读取 IPA 信息")
                    let scanned = await IPAStatusScanner.read([stage.ipa], cached: [:])[stage.ipa]
                    let metadata = scanned?.metadata
                    do {
                        let actualVersion = DownloadedIPA.versionForFilename(metadata?.version, versionID: "") ?? suggestedVersion
                        let target = direct ? try DownloadedIPA.unusedTarget(named: DownloadedIPA.filename(for: appName, noUpdate: noUpdate, version: actualVersion), in: folder) : destination
                        if let saved = await saveCompletedIPA(stage.ipa, destination: target) {
                            if paid { catalog.purchaseStatus[id] = .owned }
                            let entry = DownloadedIPA(url: saved, appName: appName, accountID: accountID, appID: id,
                                                      version: actualVersion, bundleID: metadata?.bundleID ?? app?.bundleID, stamp: try? Core.fileStamp(saved))
                            downloadedIPAs.removeAll { $0.id == entry.id }
                            downloadedIPAs.insert(entry, at: 0)
                            DownloadedIPA.save(downloadedIPAs)
                            let file = saved.standardizedFileURL
                            if let scanned, let stamp = try? Core.fileStamp(saved) {
                                ipaStatuses[file] = scanned.saved(at: file, stamp: stamp)
                            } else {
                                ipaStatuses.removeValue(forKey: file)
                            }
                            ipaFolderRevision += 1
                        }
                    } catch { alertText = error.localizedDescription }
                }
            }
        } catch { alertText = error.localizedDescription }
    }
    func showIPAReport(_ file: URL) {
        let root = store.root
        Task { @MainActor in
            do {
                let report = try await Task.detached(priority: .userInitiated) { try IPASavedReport.find(for: file, root: root) }.value
                if !runner.canReply { selectedReport = report }
            }
            catch { alertText = error.localizedDescription }
        }
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
        guard !runner.busy, store.canUseSelected, let model = store.profileURL, let accountID = store.selected else { return }
        refreshIPAReferences()
        guard !appPath.isEmpty, !setupIPA.isEmpty else { return }
        let app = appPath
        let source = URL(fileURLWithPath: setupIPA)
        let root = store.root
        Task { @MainActor in
            let prepared = await runner.fileWork("正在准备初始化 IPA…") {
                try Core.privateDirectory(model)
                guard FileManager.default.fileExists(atPath: app) else { throw DeskError("所选应用已不存在，请重新选择。") }
                let input = source.resolvingSymlinksInPath()
                guard let stamp = try Core.fileStamp(input), stamp.mode & S_IFMT == S_IFREG else {
                    throw DeskError("选择的 IPA 已不存在或不是普通文件，请重新选择。")
                }
                // The main app can read the chosen file under its own macOS privacy permissions.
                // The privileged helper opens only the private copy, outside Downloads/Desktop.
                let stage = try WorkStage.create(beside: root.appendingPathComponent("setup.ipa"), root: root, accountID: accountID)
                do {
                    try FileManager.default.copyItem(at: input, to: stage.ipa)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stage.ipa.path)
                    return stage
                } catch {
                    try? stage.cleanup()
                    throw error
                }
            }
            switch prepared {
            case .failure(let error):
                if Core.isFilePermissionError(error) {
                    alertText = "UnfairPlay 无法读取所选 IPA。请重新选取文件，或在「系统设置 → 隐私与安全性 → 文件与文件夹」允许 UnfairPlay 访问它所在的文件夹。\n\n\(error.localizedDescription)"
                } else {
                    alertText = "无法准备初始化 IPA：\(error.localizedDescription)"
                }
            case .success(let stage):
                run("authorize", ["setup", "--app", app, "--ipa", stage.ipa.path, "--model-dir", model.path], "等待系统授权并初始化", privileged: true) { ok in
                    do { try stage.cleanup() } catch {
                        let message = "临时 IPA 清理失败：\(error.localizedDescription)"
                        alertText = alertText.map { $0 + "\n\n" + message } ?? message
                    }
                    store.refreshModel(force: true)
                    if ok {
                        if Core.hasModel(model) { showCompletion("模型已初始化") }
                        else { alertText = "模型基本检查未通过，请查看模型状态。" }
                    }
                }
            }
        }
    }

}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) { DeskAppearance.apply(UserDefaults.standard.string(forKey: "deskAppearance") ?? "system"); NSApp.setActivationPolicy(.regular); NSApp.activate(ignoringOtherApps: true) }
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
        Window("UnfairPlay", id: "main") { ContentView().tint(DeskAppearance.accent) }
            .windowStyle(.hiddenTitleBar).defaultSize(width: 1080, height: 760)
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
