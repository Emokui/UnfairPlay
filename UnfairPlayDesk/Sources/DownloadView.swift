import SwiftUI
import AppKit

extension ContentView {
    var downloadView: some View {
        VStack(alignment: .leading, spacing: 20) {
            if showAppDetails, let id = Core.appID(appLink) {
                HStack {
                    Button(action: returnToSearch) { Label("搜索结果", systemImage: "chevron.left") }
                        .buttonStyle(.plain).foregroundStyle(DeskAppearance.accent)
                    Spacer()
                    if catalog.busy { ProgressView().controlSize(.small) }
                    downloadsButton(compact: true)
                }.font(.system(size: 12))
                versionBrowser(id)
            } else {
                HStack(spacing: 10) {
                    catalogSearchBar
                    downloadsButton(compact: false)
                }
                if let error = catalog.error {
                    Label(error, systemImage: "exclamationmark.circle")
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                if catalog.apps.isEmpty {
                    VStack(spacing: 10) {
                        DeskEmptyState(symbol: catalog.searched ? "magnifyingglass" : "square.grid.2x2", title: catalog.searched ? "没有找到应用" : "",
                                       message: catalog.searched ? "换个名称或搜索地区再试试。" : "输入名称、Bundle ID、App ID 或链接，\n无需登录即可浏览应用与版本记录。")
                        if let id = Core.appID(catalogQuery) {
                            Button("直接使用 App ID \(id)") { openCatalogApp(id) }.buttonStyle(.borderless).padding(.bottom, 30)
                        }
                    }.frame(maxWidth: .infinity, maxHeight: .infinity)
                } else { catalogResults }
            }
        }.padding(.bottom, 24)
            .frame(maxWidth: DeskAppearance.contentWidth, maxHeight: .infinity, alignment: .topLeading)
            .frame(maxWidth: .infinity)
            .onChange(of: catalog.source) {
                guard showAppDetails else { return }
                catalog.clearVersions()
                loadVersions()
            }
            .onAppear {
                syncAccountRegion()
                resumeCatalog()
            }
            .onDisappear { catalog.cancel() }
    }
    private var catalogSearchBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").font(.system(size: 14, weight: .light)).foregroundStyle(.secondary)
            TextField("名称、Bundle ID、ID 或链接", text: $catalogQuery)
                .textFieldStyle(.plain).font(.system(size: 12)).onSubmit(searchApps)
                .layoutPriority(1).accessibilityLabel("搜索应用")
            if !catalogQuery.isEmpty {
                Button {
                    catalogQuery = ""
                    submittedCatalogQuery = ""
                    catalog.clearSearchResults()
                } label: {
                    Image(systemName: "xmark.circle.fill").font(.system(size: 12))
                }.buttonStyle(.plain).foregroundStyle(.secondary)
                    .help("清除搜索内容").accessibilityLabel("清除搜索内容")
            }
            SearchRegionPicker(country: catalog.country, select: catalog.selectCountry)
            if catalog.busy {
                ProgressView().controlSize(.mini)
                Button("取消") { catalog.cancel() }.buttonStyle(.borderless)
            } else {
                Button("搜索", action: searchApps).buttonStyle(DeskPrimaryButtonStyle(compact: true)).fixedSize()
                    .disabled(catalogQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }.padding(.horizontal, 12).frame(height: 40).deskCard(cornerRadius: 12)
    }
    private func downloadsButton(compact: Bool) -> some View {
        Button {
            refreshIPAReferences()
            showDownloads.toggle()
        } label: {
            Image(systemName: "tray.and.arrow.down").font(.system(size: compact ? 14 : 16, weight: .medium))
                .foregroundStyle(compact ? Color.secondary : DeskAppearance.accent)
                .frame(width: compact ? 30 : 42, height: compact ? 28 : 40)
                .background {
                    if !compact {
                        RoundedRectangle(cornerRadius: 12).fill(DeskAppearance.surface)
                            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.primary.opacity(0.035)))
                    }
                }
                .contentShape(Rectangle())
        }.buttonStyle(.plain)
            .help("查看已下载 IPA").accessibilityLabel("已下载 IPA")
            .popover(isPresented: $showDownloads, arrowEdge: .bottom) { downloadsPopover }
    }
    private var downloadsPopover: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Text("已下载 IPA").font(.system(size: 14, weight: .semibold))
                Spacer()
                Button {
                    showDownloads = false
                    chooseDefaultDownloadFolder()
                } label: {
                    Image(systemName: "gearshape").font(.system(size: 13))
                }.buttonStyle(.plain).help("更改默认下载文件夹").accessibilityLabel("更改默认下载文件夹")
                Button {
                    showDownloads = false
                    if let folder = downloadDirectory() { NSWorkspace.shared.open(folder) }
                } label: {
                    Image(systemName: "folder").font(.system(size: 13))
                }.buttonStyle(.plain).help("打开默认下载文件夹").accessibilityLabel("打开默认下载文件夹")
                Button("移到废纸篓…", role: .destructive, action: confirmTrashDownloads)
                    .buttonStyle(.plain).foregroundStyle(downloadedIPAs.isEmpty || runner.busy ? Color.secondary : Color.red)
                    .disabled(downloadedIPAs.isEmpty || runner.busy)
            }
            Label(defaultDownloadFolder.path, systemImage: "folder")
                .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                .help("默认下载文件夹：\(defaultDownloadFolder.path)")
            if downloadedIPAs.isEmpty {
                Text("暂无下载记录")
                    .font(.caption).foregroundStyle(.secondary).padding(.vertical, 12)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(downloadedIPAs) { entry in
                            HStack(spacing: 4) {
                                Button {
                                    guard !Core.isMissingFile(entry.url) else {
                                        refreshIPAReferences()
                                        return
                                    }
                                    NSWorkspace.shared.activateFileViewerSelecting([entry.url])
                                } label: {
                                    HStack(spacing: 10) {
                                        Image(systemName: "doc.zipper").font(.system(size: 17)).foregroundStyle(DeskAppearance.accent)
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(entry.appName).font(.system(size: 12, weight: .medium)).lineLimit(1)
                                            Text(entry.url.lastPathComponent).font(.caption).foregroundStyle(.secondary)
                                                .lineLimit(1).truncationMode(.middle)
                                        }
                                        Spacer(minLength: 8)
                                        Image(systemName: "arrow.up.right").font(.system(size: 10)).foregroundStyle(.secondary)
                                    }.padding(.vertical, 9).padding(.horizontal, 8)
                                        .contentShape(Rectangle())
                                }.buttonStyle(.plain).help("在 Finder 中显示：\(entry.url.path)")
                                    .contextMenu {
                                        Button("去解密") { useDownloadedIPAForDecryption(entry.url) }
                                        Button("用于初始化模型") { useDownloadedIPAForSetup(entry.url) }
                                            .disabled(runner.busy || !store.canUseSelected)
                                    }
                                Button { useDownloadedIPAForDecryption(entry.url) } label: {
                                    Image(systemName: "lock.open").font(.system(size: 13)).frame(width: 26, height: 28)
                                }.buttonStyle(.plain).foregroundStyle(DeskAppearance.accent).help("去解密").accessibilityLabel("去解密")
                                Button { sendIPAWithAirDrop(entry.url) } label: {
                                    Image(systemName: "square.and.arrow.up").font(.system(size: 14))
                                        .foregroundStyle(DeskAppearance.accent).frame(width: 28, height: 28)
                                        .contentShape(Rectangle())
                                }.buttonStyle(.plain).help("通过 AirDrop 发送")
                                    .accessibilityLabel("通过 AirDrop 发送 \(entry.url.lastPathComponent)")
                            }
                            if entry.id != downloadedIPAs.last?.id { Divider().padding(.leading, 33) }
                        }
                    }
                }.frame(height: min(CGFloat(downloadedIPAs.count) * 51, 255))
            }
        }.padding(16).frame(width: 340)
            .task(id: downloadedIPAs.isEmpty) {
                guard !downloadedIPAs.isEmpty else { return }
                while !Task.isCancelled {
                    do { try await Task.sleep(for: .seconds(2)) }
                    catch { return }
                    guard !Task.isCancelled else { return }
                    refreshIPAReferences()
                }
            }
    }
    private func useDownloadedIPAForDecryption(_ url: URL) {
        guard !Core.isMissingFile(url) else { refreshIPAReferences(); return }
        showDownloads = false
        inputIPAs = []
        addInputIPAs([url])
        page = .decrypt
    }
    private func sendIPAWithAirDrop(_ url: URL) {
        guard !Core.isMissingFile(url) else {
            refreshIPAReferences()
            return
        }
        showDownloads = false
        guard let airDrop = NSSharingService(named: .sendViaAirDrop), airDrop.canPerform(withItems: [url]) else {
            alertText = "AirDrop 当前不可用。"
            return
        }
        airDrop.perform(withItems: [url])
    }
    private func useDownloadedIPAForSetup(_ url: URL) {
        guard !runner.busy, store.canUseSelected, !Core.isMissingFile(url) else {
            refreshIPAReferences()
            return
        }
        setupIPA = url.path
        showDownloads = false
        page = .account
        showModelSetup = true
    }
    private func confirmTrashDownloads() {
        guard !runner.busy else { return }
        refreshIPAReferences()
        let entries = downloadedIPAs
        guard !entries.isEmpty else { return }
        showDownloads = false

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "将已下载的 IPA 移到废纸篓？"
        if let entry = entries.first, entries.count == 1 {
            alert.informativeText = entry.url.path
        } else {
            let folders = Set(entries.map { $0.url.deletingLastPathComponent().path }).sorted()
            let locations = folders.prefix(3).joined(separator: "\n")
            let additional = folders.count > 3 ? "\n另有 \(folders.count - 3) 个文件夹。" : ""
            alert.informativeText = "将移走列表中的 \(entries.count) 个 IPA 文件，来源：\n\n\(locations)\(additional)"
        }
        alert.addButton(withTitle: "取消")
        alert.addButton(withTitle: "移到废纸篓")
        guard alert.runModal() == .alertSecondButtonReturn else { return }

        Task { @MainActor in
            let outcome = await runner.fileWork("正在将 IPA 移到废纸篓…") {
                Core.recycleIPAs(entries.map(\.url))
            }
            switch outcome {
            case .success(let (removed, failures)):
                downloadedIPAs.removeAll { removed.contains($0.id) }
                DownloadedIPA.save(downloadedIPAs)
                refreshIPAReferences()
                ipaFolderRevision += 1
                if !failures.isEmpty {
                    let details = failures.prefix(4).joined(separator: "\n")
                    alertText = "\(failures.count) 个 IPA 未能移到废纸篓，记录已保留。\n\n" + details
                }
            case .failure(let error):
                alertText = error.localizedDescription
            }
        }
    }
    private var catalogResults: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("搜索结果").font(.system(size: 12, weight: .medium))
                Text("\(catalog.apps.count) 个应用").font(.caption).foregroundStyle(.secondary)
                Spacer()
            }
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(catalog.apps) { app in
                        Button { openCatalogApp(String(app.id)) } label: {
                            HStack(spacing: 16) {
                                catalogIcon(app, size: 42)
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(app.name).font(.system(size: 12, weight: .medium)).lineLimit(1)
                                    Text(app.artist ?? app.bundleID).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                }
                                Spacer(minLength: 12)
                                VStack(alignment: .trailing, spacing: 4) {
                                    HStack(spacing: 8) {
                                        if let version = app.version { Text(version) }
                                        if let price = app.priceText { Text(price).foregroundStyle(DeskAppearance.accent) }
                                    }
                                    if let size = app.sizeText { Text(size).monospacedDigit() }
                                }.font(.caption).foregroundStyle(.secondary)
                                Image(systemName: "chevron.right").font(.system(size: 11, weight: .medium)).foregroundStyle(.tertiary)
                            }.padding(18).contentShape(Rectangle())
                        }.buttonStyle(.plain)
                        if app.id != catalog.apps.last?.id { Divider().padding(.leading, 82).padding(.trailing, 18) }
                    }
                }.deskCard()
            }.scrollIndicators(.hidden)
        }.frame(maxHeight: .infinity)
    }
    private func catalogIcon(_ app: CatalogApp?, size: CGFloat) -> some View {
        AsyncImage(url: app?.artwork) { image in image.resizable().scaledToFit() } placeholder: {
            RoundedRectangle(cornerRadius: 12).fill(DeskAppearance.accent.opacity(0.07))
                .overlay(Image(systemName: "app").font(.system(size: size * 0.45, weight: .light)).foregroundStyle(DeskAppearance.accent))
        }.frame(width: size, height: size).clipShape(RoundedRectangle(cornerRadius: size * 0.22))
    }
    private func openCatalogApp(_ id: String) {
        preventAppStoreUpdates = false
        appLink = id; catalog.selectApp(id); showAppDetails = true; showVersionEntry = false; loadVersions()
    }
    func versionBrowser(_ id: String) -> some View {
        let app = catalog.app(for: id)
        let loadingName = catalog.isWaitingForAppName(id)
        return VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 18) {
                catalogIcon(app, size: 54)
                VStack(alignment: .leading, spacing: 8) {
                    Text(app?.name ?? "App ID \(id)").font(.system(size: 18, weight: .medium)).lineLimit(2)
                    Text(app?.artist ?? "从 Apple 获取所选版本")
                        .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                    if let bundleID = app?.bundleID {
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(bundleID, forType: .string)
                        } label: {
                            HStack(spacing: 5) {
                                Text(bundleID).lineLimit(1).truncationMode(.middle)
                                Image(systemName: "doc.on.doc").font(.system(size: 9))
                            }
                        }.buttonStyle(.plain).font(.system(size: 10)).foregroundStyle(.secondary)
                            .help("复制 Bundle ID").accessibilityLabel("复制 Bundle ID \(bundleID)")
                    }
                }
                Spacer(minLength: 0)
                if let price = app?.priceText {
                    VStack(alignment: .trailing, spacing: 4) {
                        Text(price).font(.system(size: 13, weight: .medium)).monospacedDigit()
                        if let status = catalog.purchaseStatus[id] {
                            Text(status.text).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if let size = app?.sizeText {
                    VStack(alignment: .trailing, spacing: 4) {
                        Text(size).font(.system(size: 13, weight: .medium)).monospacedDigit()
                        Text("最新版大小").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }.padding(.vertical, 4)
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    Text("版本记录").font(.system(size: 12, weight: .medium))
                    if catalog.versionsLoaded { Text("\(catalog.versions.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
                    Spacer()
                    Picker("版本来源", selection: $catalog.source) {
                        ForEach(VersionSource.allCases) { Text($0.rawValue).tag($0) }
                    }.labelsHidden().fixedSize().controlSize(.small)
                    Button(action: loadVersions) { Image(systemName: "arrow.clockwise") }
                        .buttonStyle(.borderless).help("刷新版本记录").disabled(catalog.busy)
                }.padding(20)
                if let error = catalog.error {
                    Label(error, systemImage: "exclamationmark.circle")
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                        .padding(.horizontal, 20).padding(.bottom, 12)
                }
                HStack {
                    Text("版本").frame(maxWidth: .infinity, alignment: .leading)
                    Text("记录日期").frame(width: 100, alignment: .leading)
                    Text("版本 ID").frame(width: 126, alignment: .trailing)
                }.font(.system(size: 10, weight: .medium)).foregroundStyle(.secondary).padding(.horizontal, 22).padding(.bottom, 12)
                Divider().padding(.horizontal, 20)
                ScrollView {
                    LazyVStack(spacing: 2) {
                        versionRow(version: app?.version.map { "\($0) · 最新版" } ?? "最新版本", identifier: "", date: "—")
                        ForEach(catalog.versions) { version in
                            versionRow(version: catalog.details[version.id]?.displayVersion ?? version.version,
                                       identifier: version.id, date: version.date.isEmpty ? "—" : String(version.date.prefix(10)))
                        }
                        if catalog.versionsLoaded && catalog.versions.isEmpty {
                            Text("此来源暂无历史记录，可切换来源或指定版本 ID。")
                                .font(.caption).foregroundStyle(.secondary).padding(24)
                        }
                    }.padding(8)
                }.scrollIndicators(.hidden).frame(maxHeight: .infinity)
            }.deskCard().frame(maxHeight: .infinity)
            VStack(alignment: .leading, spacing: 12) {
                if showVersionEntry {
                    HStack(spacing: 12) {
                        TextField("指定版本 ID（留空下载最新版）", text: $catalog.selectedVersion)
                            .textFieldStyle(.roundedBorder).onSubmit(loadVersionMetadata)
                        Button("读取信息", action: loadVersionMetadata)
                            .disabled(runner.busy || catalog.selectedVersion.isEmpty || !catalog.validVersion || !canDownload)
                    }
                    if !catalog.validVersion { Text("版本 ID 应为正整数。").font(.caption).foregroundStyle(.orange) }
                    if let detail = catalog.details[catalog.selectedVersion] {
                        Text("版本 \(detail.displayVersion)" + (detail.dateText.map { " · 包内日期 \($0)" } ?? ""))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if let error = catalog.metadataError { Text(error).font(.caption).foregroundStyle(.secondary) }
                }
                HStack(spacing: 16) {
                    Button(showVersionEntry ? "收起版本 ID" : "指定版本 ID") { showVersionEntry.toggle() }
                        .buttonStyle(.plain).font(.caption).foregroundStyle(.secondary)
                    Toggle("直接保存", isOn: $saveIPAsDirectly).toggleStyle(.checkbox).font(.caption).controlSize(.small)
                        .help("直接保存到默认下载文件夹，同名文件追加序号").disabled(runner.busy)
                    Toggle("不再更新", isOn: $preventAppStoreUpdates).toggleStyle(.checkbox)
                        .font(.caption).controlSize(.small)
                        .disabled(runner.busy || catalog.purchaseStatus[id] == .unowned)
                        .help("保存时移除 IPA 的 App Store 更新识别元数据")
                    Spacer()
                    if needsSelectedLogin, let account = store.selectedProfile {
                        Text("登录会话失效").font(.caption).foregroundStyle(.secondary)
                        Button("重新登录") { login(account) }
                            .buttonStyle(DeskPrimaryButtonStyle()).controlSize(.large)
                            .disabled(runner.busy || !store.canUseSelected)
                    } else if let price = app?.priceText, catalog.purchaseStatus[id] == .unowned {
                        Button {
                            if let url = URL(string: "https://apps.apple.com/\(catalog.country.lowercased())/app/id\(id)") {
                                if NSWorkspace.shared.open(url) { purchasePageAppID = id }
                            }
                        } label: {
                            Label("在 App Store 查看 · \(price)", systemImage: "arrow.up.right")
                        }.buttonStyle(DeskPrimaryButtonStyle()).controlSize(.large)
                            .help("打开 App Store 商品页")
                    } else {
                        Button(action: download) {
                            Label("下载", systemImage: "arrow.down").frame(minWidth: 126)
                        }.buttonStyle(DeskPrimaryButtonStyle()).controlSize(.large)
                            .disabled(runner.busy || !canDownload || !catalog.validVersion || loadingName)
                            .help(canDownload ? "从 Apple 下载 IPA" : "请先添加并登录 Apple ID")
                    }
                }
                Text("IPA 由 Apple 提供，使用当前账户的商店地区与许可。").font(.system(size: 10)).foregroundStyle(.tertiary)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .task(id: "\(id):\(catalog.country):\(store.selected?.uuidString ?? "")") {
                await catalog.lookUpAppName(id)
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                if purchasePageAppID == id {
                    purchasePageAppID = nil
                    catalog.purchaseStatus[id] = nil
                }
            }
    }
    private func versionRow(version: String, identifier: String, date: String) -> some View {
        Button { catalog.selectedVersion = identifier } label: {
            HStack(spacing: 8) {
                Image(systemName: catalog.selectedVersion == identifier ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(catalog.selectedVersion == identifier ? DeskAppearance.accent : Color.secondary.opacity(0.25)).frame(width: 16)
                Text(version).font(.system(size: 12, weight: .medium)).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
                Text(date).font(.system(size: 11)).foregroundStyle(.secondary).frame(width: 100, alignment: .leading)
                Text(identifier.isEmpty ? "自动选择" : identifier).font(.system(size: 11).monospacedDigit())
                    .foregroundStyle(.secondary).frame(width: 126, alignment: .trailing)
            }.padding(.horizontal, 14).padding(.vertical, 13).contentShape(Rectangle())
                .background(catalog.selectedVersion == identifier ? DeskAppearance.accent.opacity(0.07) : .clear, in: RoundedRectangle(cornerRadius: 9))
        }.buttonStyle(.plain)
    }
    func syncAccountRegion() {
        guard let account = store.selectedProfile, account.appleID != nil,
              account.loginCleared != true, store.canUseSelected else {
            catalog.updateAccountCountry(nil)
            return
        }
        catalog.updateAccountCountry(account.storeFront)
    }
    func resumeCatalog() {
        if showAppDetails, Core.appID(appLink) != nil {
            if !catalog.busy && catalog.error == nil && !catalog.versionsLoaded { loadVersions() }
        } else if !catalog.busy && catalog.error == nil && !submittedCatalogQuery.isEmpty && !catalog.searched {
            catalog.search(submittedCatalogQuery)
        }
    }
    private func returnToSearch() {
        showAppDetails = false
        catalog.selectApp(nil)
        resumeCatalog()
    }
    func searchApps() {
        let term = catalogQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !term.isEmpty else { return }
        submittedCatalogQuery = term
        showAppDetails = false; catalog.selectApp(nil); catalog.search(term)
    }
    func loadVersions() {
        guard let id = Core.appID(appLink) else { return }
        catalog.selectApp(id); catalog.loadPublicHistory()
    }
    func loadVersionMetadata() {
        let version = catalog.selectedVersion
        catalog.metadataError = nil
        guard !runner.busy, let id = Core.appID(appLink), !version.isEmpty, catalog.validVersion,
              canDownload, catalog.details[version] == nil else { return }
        let account = store.selected
        run("ipatool", ["get-version-metadata", "--app-id", id, "--external-version-id", version, "--platform", "iphone"], "正在读取所选版本信息") { ok in
            guard store.selected == account, showAppDetails, Core.appID(appLink) == id else { return }
            guard ok else {
                guard !runner.cancelled else { return }
                if runner.title == "账户身份校验未通过" {
                    catalog.metadataError = alertText
                    return
                }
                let lower = runner.output.lowercased()
                let authOrKeychainFailure = (account.map(accountsNeedingLogin.contains) == true) ||
                    lower.contains("read macos keychain item") || lower.contains("encrypted account session") ||
                    lower.contains("account session key is") || lower.contains("keychain passphrase")
                catalog.metadataError = authOrKeychainFailure ? Core.errorHint(runner.output) : "版本信息暂不可用，仍可按版本 ID 尝试下载。"
                return
            }
            do {
                let detail = try DownloadCatalog.response(CatalogVersion.self, in: runner.output)
                guard detail.externalVersionID == version else { throw DeskError("返回的版本 ID 不匹配。") }
                catalog.details[version] = detail
            } catch { catalog.metadataError = error.localizedDescription }
        }
    }
}
