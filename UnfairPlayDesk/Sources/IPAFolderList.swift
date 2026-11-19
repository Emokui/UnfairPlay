import SwiftUI
import AppKit

private enum IPAListFilter: String, CaseIterable {
    case all = "全部", encrypted = "未解密", clear = "已解密"
    func includes(_ status: IPAEncryptionStatus) -> Bool {
        self == .all || (self == .encrypted && status == .encrypted) || (self == .clear && status == .clear)
    }
}

struct IPAFolderList: View {
    let folder: URL
    let revision: Int
    @Binding var selection: [URL]
    let additionalFiles: [URL]
    @Binding var statuses: [URL: IPAStatusEntry]
    let profiles: [Profile]
    let selectedAccount: UUID?
    let modelSelectors: [UUID: Set<String>]
    let modelCheckStates: [UUID: ModelCheckState]
    let downloads: [DownloadedIPA]
    let canSwitchAccount: Bool
    let switchAccount: (UUID) -> Void
    let viewReport: (URL) -> Void
    let changeFolder: () -> Void
    let browse: () -> Void
    @ViewState private var listing: Listing?
    @ViewState private var query = ""
    @ViewState private var filter: IPAListFilter = .all

    private struct Listing { let folder: URL; let result: Result<[URL], Error> }

    var body: some View {
        let scan = IPAFolderScan(folder: folder, revision: revision, additionalFiles: additionalFiles, selection: selection)
        let current = listing?.folder == folder ? listing?.result : nil
        let listedFiles = (try? current?.get()) ?? []
        var directoryFiles = Set(listedFiles)
        let selectedFiles = Set(selection.map(\.standardizedFileURL))
        let external = (additionalFiles + selection).map(\.standardizedFileURL).filter { directoryFiles.insert($0).inserted }
        let externalFiles = Set(external)
        let files = listedFiles + external
        let visible = files.filter { matches($0) && filter.includes(statuses[$0]?.status ?? .unknown) }
        let groups = Dictionary(grouping: visible) { statuses[$0]?.status ?? .unknown }
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "folder").font(.system(size: 17)).foregroundStyle(DeskAppearance.accent)
                VStack(alignment: .leading, spacing: 4) {
                    Text("默认下载文件夹").font(.system(size: 12, weight: .semibold))
                    Text(folder.path).font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle).help(folder.path)
                }
                Spacer(minLength: 8)
                Button("更改…", action: changeFolder).controlSize(.small)
                Button("添加 IPA…", action: browse).controlSize(.small)
            }.padding(16)
            HStack(spacing: 16) {
                HStack(spacing: 7) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("应用、Bundle ID 或文件名", text: $query).textFieldStyle(.plain)
                    if !query.isEmpty {
                        Button { query = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                            .buttonStyle(.plain).help("清除筛选")
                    }
                }.font(.system(size: 11)).padding(8).background(DeskAppearance.background, in: RoundedRectangle(cornerRadius: 8))
                Picker("文件状态", selection: $filter) {
                    ForEach(IPAListFilter.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented).labelsHidden().frame(width: 220)
            }.padding(.horizontal, 16).padding(.bottom, 14)
            Divider()
            Group {
                if !visible.isEmpty {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 10) {
                            ForEach(IPAEncryptionStatus.allCases, id: \.self) { status in
                                if let group = groups[status] {
                                    fileSection(group, status: status, selected: selectedFiles, external: externalFiles)
                                }
                            }
                        }.padding(8)
                    }
                } else if case .some(.failure(let error)) = current {
                    DeskEmptyState(symbol: "folder.badge.questionmark", title: "无法读取默认下载文件夹", message: error.localizedDescription)
                } else if !files.isEmpty {
                    DeskEmptyState(symbol: "magnifyingglass", title: "没有匹配的 IPA", message: "调整关键词或文件状态筛选。")
                } else if current == nil {
                    ProgressView().controlSize(.small)
                } else {
                    DeskEmptyState(symbol: "doc.zipper", title: "文件夹中没有 IPA", message: "可添加本机 IPA，或将文件拖到此处。")
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            HStack {
                Label("也可以将 IPA 拖到这里", systemImage: "arrow.down.to.line").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if !selection.isEmpty {
                    Text("已选 \(selection.count) 份").font(.caption).foregroundStyle(.secondary)
                    Button("取消选择") { selection = [] }.buttonStyle(.borderless).controlSize(.small)
                }
            }.padding(.horizontal, 16).padding(.vertical, 10)
        }.deskCard().contentShape(Rectangle())
        .task(id: scan) {
            await scan.run(cache: { statuses },
                           listed: { listing = Listing(folder: folder, result: $0) },
                           apply: { statuses = $0 })
        }
    }

    private func matches(_ file: URL) -> Bool {
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !term.isEmpty else { return true }
        let metadata = statuses[file]?.metadata
        return [file.lastPathComponent, metadata?.name ?? "", metadata?.bundleID ?? ""].contains { $0.localizedCaseInsensitiveContains(term) }
    }

    private func modelHint(_ file: URL) -> IPAModelHint? {
        guard let entry = statuses[file] else { return nil }
        return IPAModelHint.resolve(entry.metadata, profiles: profiles, selected: selectedAccount,
                                    selectors: modelSelectors, states: modelCheckStates)
    }

    private func origin(_ file: URL) -> String? {
        guard let entry = statuses[file],
              let source = downloads.first(where: { $0.url.standardizedFileURL == file && $0.stamp == entry.stamp }),
              let id = source.accountID else { return nil }
        return "下载档案 · " + (profiles.first { $0.id == id }?.name ?? "已删除档案")
    }

    private func fileSection(_ files: [URL], status: IPAEncryptionStatus, selected: Set<URL>, external: Set<URL>) -> some View {
        LazyVStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(status.title).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                Text("\(files.count)").font(.caption.monospacedDigit()).foregroundStyle(.tertiary)
                Spacer()
                if status == .encrypted {
                    Button("全选未解密") { selection.append(contentsOf: files.filter { !selected.contains($0) }) }
                        .buttonStyle(.borderless).controlSize(.small).disabled(files.allSatisfy { selected.contains($0) })
                }
            }.padding(.horizontal, 10).padding(.top, 5)
            ForEach(files, id: \.self) { file in
                HStack(spacing: 6) {
                    Button { toggle(file) } label: { fileRow(file, selected: selected.contains(file), external: external.contains(file)) }
                        .buttonStyle(.plain)
                    if let account = modelHint(file)?.account {
                        Button("切换") { switchAccount(account) }.controlSize(.small)
                            .disabled(!canSwitchAccount).padding(.trailing, 10)
                    }
                }.background(selected.contains(file) ? DeskAppearance.accent.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 8))
                    .contextMenu {
                        Button("在 Finder 中显示") { NSWorkspace.shared.activateFileViewerSelecting([file]) }
                        Button("查看解密报告") { viewReport(file) }
                    }
            }
        }.padding(7).background(DeskAppearance.background, in: RoundedRectangle(cornerRadius: 9))
    }

    private func toggle(_ file: URL) {
        let remaining = selection.filter { $0.standardizedFileURL != file }
        if remaining.count != selection.count { selection = remaining }
        else { selection.append(file) }
    }

    private func fileRow(_ file: URL, selected: Bool, external: Bool) -> some View {
        let entry = statuses[file]
        let metadata = entry?.metadata
        return HStack(spacing: 11) {
            Group {
                if let icon = entry?.icon { Image(nsImage: icon).resizable().scaledToFit() }
                else { Image(systemName: "doc.zipper").font(.system(size: 23, weight: .light)).foregroundStyle(DeskAppearance.accent) }
            }.frame(width: 36, height: 36).clipShape(RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    Text(metadata?.name ?? file.lastPathComponent).font(.system(size: 12, weight: .medium)).lineLimit(1)
                    if let version = metadata?.version, !version.isEmpty { Text(version).font(.caption).foregroundStyle(.secondary) }
                }
                if let bundle = metadata?.bundleID, !bundle.isEmpty {
                    Text(bundle).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                }
                HStack(spacing: 8) {
                    if let origin = origin(file) { Text(origin) }
                    if let hint = modelHint(file) { Text(hint.text) }
                }.font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                Text(external ? file.path : file.lastPathComponent).font(.system(size: 9)).foregroundStyle(.tertiary)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 6)
            if let size = metadata?.bytes {
                Text(ByteCountFormatter.string(fromByteCount: size, countStyle: .file)).font(.system(size: 10)).foregroundStyle(.secondary).fixedSize()
            }
            Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(selected ? DeskAppearance.accent : Color.secondary.opacity(0.35))
        }.padding(.horizontal, 10).padding(.vertical, 10).frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle()).help(file.path).accessibilityAddTraits(selected ? .isSelected : [])
    }

}
