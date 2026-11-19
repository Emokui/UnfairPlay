import Foundation

struct IPAFolderScan: Equatable {
    let folder: URL
    let revision: Int
    let externalFiles: [URL]

    init(folder: URL, revision: Int, additionalFiles: [URL], selection: [URL]) {
        let directory = folder.standardizedFileURL
        self.folder = directory
        self.revision = revision
        let outsideSelection = selection.map(\.standardizedFileURL).filter { $0.deletingLastPathComponent() != directory }
        externalFiles = Array(Set(additionalFiles.map(\.standardizedFileURL) + outsideSelection)).sorted { $0.path < $1.path }
    }

    @MainActor func run(cache: () -> [URL: IPAStatusEntry],
                        listed: (Result<[URL], Error>) -> Void,
                        apply: ([URL: IPAStatusEntry]) -> Void,
                        read: ([URL], [URL: IPAStatusEntry]) async -> [URL: IPAStatusEntry] = IPAStatusScanner.read) async {
        let directory = folder
        let listing = await Task.detached(priority: .userInitiated) {
            Result { try Self.files(in: directory) }
        }.value
        guard !Task.isCancelled else { return }
        listed(listing)
        var files = (try? listing.get()) ?? []
        var known = Set(files)
        files.append(contentsOf: externalFiles.filter { known.insert($0).inserted })
        let baseline = cache()
        let scanned = await read(files, baseline)
        guard !Task.isCancelled else { return }
        var current = cache()
        for (file, entry) in scanned where current[file]?.stamp != entry.stamp && current[file]?.stamp == baseline[file]?.stamp {
            if (try? Core.fileStamp(file.resolvingSymlinksInPath())) == entry.stamp { current[file] = entry }
        }
        apply(current)
    }

    private static func files(in directory: URL) throws -> [URL] {
        let entries = try FileManager.default.contentsOfDirectory(at: directory,
            includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles])
        return entries.filter {
            $0.pathExtension.lowercased() == "ipa" && (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
        }.map(\.standardizedFileURL).sorted { $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending }
    }
}
