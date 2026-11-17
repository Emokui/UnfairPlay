import Foundation

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

struct IPAStatusEntry {
    let stamp: Core.FileStamp
    let status: IPAEncryptionStatus
}

enum IPAStatusScanner {
    private struct Response: Decodable {
        let path: String
        let status: IPAEncryptionStatus
    }

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
                    if let status = responses[file.path] {
                        result[file] = IPAStatusEntry(stamp: stamp, status: status)
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

    private static func inspect(_ paths: [String], tools: URL, scan: ScanProcess) -> [String: IPAEncryptionStatus] {
        let process = Process()
        process.executableURL = tools.appendingPathComponent("worker")
        process.arguments = ["--parent", String(ProcessInfo.processInfo.processIdentifier),
                             tools.appendingPathComponent("unfairplay").path, "ipa-status", "--"] + paths
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? scan.start(process)) == true else { return [:] }
        defer { scan.finished() }
        let response = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0,
              let items = try? JSONDecoder().decode([Response].self, from: response) else { return [:] }
        return Dictionary(items.map { ($0.path, $0.status) }, uniquingKeysWith: { _, item in item })
    }
}
