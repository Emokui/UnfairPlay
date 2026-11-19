import Foundation
import AppKit
import ImageIO

enum IPAEncryptionStatus: String, Decodable, CaseIterable {
    case encrypted, clear, unknown

    var title: String {
        switch self {
        case .encrypted: "未解密"
        case .clear: "已解密 / 无加密标记"
        case .unknown: "状态未确认"
        }
    }
}

struct IPAMetadata: Decodable {
    var path: String
    let status: IPAEncryptionStatus
    let name: String?
    let bundleID: String?
    let version: String?
    let build: String?
    let bytes: Int64?
    var icon: Data?
    let selectorIDs: [String]?
    let selectorScanComplete: Bool?
    enum CodingKeys: String, CodingKey {
        case path, status, name, version, build, bytes, icon
        case bundleID = "bundle_id", selectorIDs = "selector_ids", selectorScanComplete = "selector_scan_complete"
    }
}

struct IPAStatusEntry {
    let stamp: Core.FileStamp
    let metadata: IPAMetadata
    let icon: NSImage?
    var status: IPAEncryptionStatus { metadata.status }

    func saved(at url: URL, stamp: Core.FileStamp) -> Self {
        var metadata = metadata
        metadata.path = url.path
        return Self(stamp: stamp, metadata: metadata, icon: icon)
    }
}

struct IPAModelHint {
    let text: String
    var account: UUID?

    static func resolve(_ metadata: IPAMetadata, profiles: [Profile], selected: UUID?,
                        selectors: [UUID: Set<String>], states: [UUID: ModelCheckState]) -> Self? {
        guard metadata.status != .clear else { return nil }
        let required = Set(metadata.selectorIDs ?? [])
        guard metadata.selectorScanComplete == true, !required.isEmpty else {
            return Self(text: "许可信息未确认")
        }
        let active = profiles.filter { $0.deletionPending != true }
        let candidates = active.filter { states[$0.id] == .valid && required.isSubset(of: selectors[$0.id] ?? []) }
        if let profile = candidates.first(where: { $0.id == selected }) ?? candidates.first {
            return Self(text: profile.id == selected ? "当前档案模型匹配" : "匹配模型 · \(profile.name)",
                        account: profile.id == selected ? nil : profile.id)
        }
        if active.contains(where: { states[$0.id] == nil || states[$0.id] == .checking }) {
            return Self(text: "正在校验模型…")
        }
        if active.contains(where: { states[$0.id] == .valid && (selectors[$0.id] ?? []).isEmpty }) {
            return Self(text: "模型关联待确认")
        }
        let partial = active.contains { !(selectors[$0.id] ?? []).isDisjoint(with: required) }
        return Self(text: partial ? "部分许可匹配" : "尚未找到匹配模型")
    }
}

enum IPAStatusScanner {
    private final class ScanProcess: @unchecked Sendable {
        private let lock = NSLock()
        private var running: Process?
        private var cancelled = false

        func start(_ process: Process) throws -> Bool {
            try lock.withLock {
                guard !cancelled else { return false }
                try process.run()
                running = process
                return true
            }
        }

        func finished() {
            lock.withLock { running = nil }
        }

        func cancel() {
            lock.withLock {
                cancelled = true
                if let running, running.isRunning { running.terminate() }
            }
        }
    }

    static func read(_ files: [URL], cached: [URL: IPAStatusEntry]) async -> [URL: IPAStatusEntry] {
        guard !files.isEmpty else { return [:] }
        guard (try? await Core.bundleVerification.value) != nil,
              let tools = Bundle.main.resourceURL?.appendingPathComponent("Tools") else { return [:] }
        let scan = ScanProcess()
        let work = Task.detached(priority: .utility) {
            var result: [URL: IPAStatusEntry] = [:]
            var pending: [(URL, Core.FileStamp)] = []
            for file in files {
                if Task.isCancelled { return result }
                guard let stamp = try? Core.fileStamp(file.resolvingSymlinksInPath()) else { continue }
                if let entry = cached[file], entry.stamp == stamp {
                    result[file] = entry
                } else {
                    pending.append((file, stamp))
                }
            }

            for start in stride(from: 0, to: pending.count, by: 24) {
                if Task.isCancelled { break }
                let items = pending[start..<min(start + 24, pending.count)]
                let paths = items.map { $0.0.path }
                let responses = inspect(paths, tools: tools, scan: scan)
                for (file, stamp) in items where (try? Core.fileStamp(file.resolvingSymlinksInPath())) == stamp {
                    if var metadata = responses[file.path] {
                        let icon = metadata.icon.flatMap(thumbnail)
                        metadata.icon = nil
                        result[file] = IPAStatusEntry(stamp: stamp, metadata: metadata, icon: icon)
                    }
                }
            }
            return result
        }
        return await withTaskCancellationHandler {
            await work.value
        } onCancel: {
            work.cancel()
            scan.cancel()
        }
    }

    private static func thumbnail(_ data: Data) -> NSImage? {
        let options: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true,
                                       kCGImageSourceThumbnailMaxPixelSize: 80,
                                       kCGImageSourceShouldCacheImmediately: true]
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else { return nil }
        return NSImage(cgImage: image, size: NSSize(width: 36, height: 36))
    }

    private static func inspect(_ paths: [String], tools: URL, scan: ScanProcess) -> [String: IPAMetadata] {
        let process = Process()
        process.executableURL = tools.appendingPathComponent("worker")
        process.arguments = ["--parent", String(ProcessInfo.processInfo.processIdentifier),
                             tools.appendingPathComponent("unfairplay").path, "ipa-status", "--metadata", "--"] + paths
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? scan.start(process)) == true else { return [:] }
        defer { scan.finished() }
        let response = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0,
              let items = try? JSONDecoder().decode([IPAMetadata].self, from: response) else { return [:] }
        return Dictionary(items.map { ($0.path, $0) }, uniquingKeysWith: { _, item in item })
    }
}
