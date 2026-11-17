import SwiftUI
import AppKit

struct IPAFolderList: View {
    let folder: URL
    let revision: Int
    @Binding var selection: [URL]
    let additionalFiles: [URL]
    @Binding var statuses: [URL: IPAStatusEntry]
    let changeFolder: () -> Void
    let browse: () -> Void
    @ViewState private var listing: Listing? = nil

    private struct Scan: Equatable {
        let folder: URL
        let revision: Int
    }

    private struct Listing {
        let folder: URL
        let result: Result<[URL], Error>
    }
    private struct StatusScan: Equatable {
        let files: [URL]
        let revision: Int
    }

    var body: some View {
        let current = listing?.folder == folder ? listing?.result : nil
        let listedFiles = (try? current?.get()) ?? []
        var directoryFiles = Set(listedFiles)
        let selectedFiles = Set(selection)
        let external = (additionalFiles + selection).filter { directoryFiles.insert($0).inserted }
        let externalFiles = Set(external)
        let files = listedFiles + external
        let groups = Dictionary(grouping: files) { statuses[$0]?.status ?? .unknown }
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
            Divider()

            Group {
                if !files.isEmpty {
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
                    DeskEmptyState(symbol: "folder.badge.questionmark", title: "无法读取默认下载文件夹",
                                   message: error.localizedDescription)
                } else if current == nil {
                    ProgressView().controlSize(.small)
                } else {
                    DeskEmptyState(symbol: "doc.zipper", title: "文件夹中没有 IPA", message: "可添加本机 IPA，或将文件拖到此处。")
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()
            HStack {
                Label("也可以将 IPA 拖到这里", systemImage: "arrow.down.to.line")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                if !selection.isEmpty {
                    Text("已选 \(selection.count) 份").font(.caption).foregroundStyle(.secondary)
                    Button("取消选择") { selection = [] }.buttonStyle(.borderless).controlSize(.small)
                }
            }.padding(.horizontal, 16).padding(.vertical, 10)
        }
        .deskCard()
        .contentShape(Rectangle())
        .task(id: Scan(folder: folder, revision: revision)) {
            let directory = folder
            let result = await Task.detached(priority: .userInitiated) {
                Result { try Self.files(in: directory) }
            }.value
            guard !Task.isCancelled else { return }
            listing = Listing(folder: directory, result: result)
        }
        .task(id: StatusScan(files: files, revision: revision)) {
            let result = await IPAStatusScanner.read(files, cached: statuses)
            if !Task.isCancelled { statuses = result }
        }
    }

    private func fileSection(_ files: [URL], status: IPAEncryptionStatus, selected: Set<URL>, external: Set<URL>) -> some View {
        LazyVStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(status.title).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                Spacer()
                if status == .encrypted {
                    Button("全选未解密") {
                        selection.append(contentsOf: files.filter { !selected.contains($0) })
                    }.buttonStyle(.borderless).controlSize(.small)
                        .disabled(files.allSatisfy { selected.contains($0) })
                }
            }.padding(.horizontal, 10).padding(.top, 5)
            ForEach(files, id: \.self) { file in
                Button { toggle(file) } label: {
                    fileRow(file, selected: selected.contains(file), external: external.contains(file))
                }.buttonStyle(.plain)
                    .contextMenu {
                        Button("在 Finder 中显示") { NSWorkspace.shared.activateFileViewerSelecting([file]) }
                    }
            }
        }.padding(7)
            .background(DeskAppearance.background, in: RoundedRectangle(cornerRadius: 9))
    }

    private func toggle(_ file: URL) {
        if let index = selection.firstIndex(of: file) { selection.remove(at: index) }
        else { selection.append(file) }
    }

    private func fileRow(_ file: URL, selected: Bool, external: Bool) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "doc.zipper").foregroundStyle(DeskAppearance.accent).frame(width: 18)
            VStack(alignment: .leading, spacing: 3) {
                Text(file.lastPathComponent).lineLimit(1).truncationMode(.middle)
                if external {
                    Text(file.deletingLastPathComponent().path).font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer()
            Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(selected ? DeskAppearance.accent : Color.secondary.opacity(0.35))
        }
        .padding(.horizontal, 10).padding(.vertical, 9)
        .background(selected ? DeskAppearance.accent.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 8))
        .contentShape(Rectangle())
        .help(file.path)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    nonisolated private static func files(in directory: URL) throws -> [URL] {
        let entries = try FileManager.default.contentsOfDirectory(at: directory,
            includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles])
        return entries.filter { file in
            file.pathExtension.lowercased() == "ipa" &&
                (try? file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
        }.map(\.standardizedFileURL)
            .sorted { $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending }
    }
}
