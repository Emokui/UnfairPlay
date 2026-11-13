import Foundation
import Darwin

struct WorkStage {
    let id: UUID
    let directory: URL
    let registry: URL
    var ipa: URL { directory.appendingPathComponent("result.ipa") }
    var report: URL { directory.appendingPathComponent("report.json") }
    static func create(beside target: URL, root: URL, accountID: UUID? = nil) throws -> WorkStage {
        let id = UUID()
        let parent = target.deletingLastPathComponent().resolvingSymlinksInPath()
        let dir = parent.appendingPathComponent(".unfairplay-work-\(id.uuidString)")
        try Core.privateDirectory(dir)
        do {
        let marker = dir.appendingPathComponent(".desk-job")
        try Data(id.uuidString.utf8).write(to: marker)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: marker.path)
        let jobs = root.appendingPathComponent("Jobs"); try Core.privateDirectory(jobs)
        let registry = jobs.appendingPathComponent("\(id.uuidString).json")
        var metadata: [String: Any] = ["id": id.uuidString, "path": dir.path, "pid": getpid()]
        metadata["account_profile_id"] = accountID?.uuidString
        try Core.writeJSON(metadata, to: registry)
        return WorkStage(id: id, directory: dir, registry: registry)
        } catch { try? FileManager.default.removeItem(at: dir); throw error }
    }
    func cleanup() throws {
        if FileManager.default.fileExists(atPath: directory.path) {
            try Core.ordinaryDirectory(directory)
            let marker = try String(contentsOf: directory.appendingPathComponent(".desk-job"), encoding: .utf8)
            guard marker == id.uuidString, directory.lastPathComponent == ".unfairplay-work-\(id.uuidString)" else { throw DeskError("临时目录标识不匹配，已停止自动清理。") }
            try FileManager.default.removeItem(at: directory)
        }
        if FileManager.default.fileExists(atPath: registry.path) { try FileManager.default.removeItem(at: registry) }
    }
    static func recover(root: URL) throws {
        let jobs = root.appendingPathComponent("Jobs")
        guard FileManager.default.fileExists(atPath: jobs.path) else { return }
        try Core.ordinaryDirectory(jobs)
        for file in try FileManager.default.contentsOfDirectory(at: jobs, includingPropertiesForKeys: nil) where file.pathExtension == "json" {
            let json = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any]
            guard let value = json?["id"] as? String, let id = UUID(uuidString: value),
                  let path = json?["path"] as? String, let pid = json?["pid"] as? Int32,
                  file.deletingPathExtension().lastPathComponent == id.uuidString else { throw DeskError("临时任务记录损坏，请检查 Jobs 目录。") }
            if kill(pid, 0) == 0 { continue }
            try WorkStage(id: id, directory: URL(fileURLWithPath: path), registry: file).cleanup()
        }
    }
    static func removeAccountJobs(_ account: UUID, root: URL) throws {
        let jobs = root.appendingPathComponent("Jobs")
        guard FileManager.default.fileExists(atPath: jobs.path) else { return }
        try Core.ordinaryDirectory(jobs)
        for file in try FileManager.default.contentsOfDirectory(at: jobs, includingPropertiesForKeys: nil) where file.pathExtension == "json" {
            let json = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any]
            guard let owner = json?["account_profile_id"] as? String, UUID(uuidString: owner) == account else { continue }
            guard let idText = json?["id"] as? String, let id = UUID(uuidString: idText), let path = json?["path"] as? String, let pid = json?["pid"] as? Int32 else { throw DeskError("账户临时任务记录损坏，清理已停止。") }
            guard pid == getpid() || kill(pid, 0) != 0 else { throw DeskError("此账户仍有另一个实例的任务正在运行，暂不能删除。") }
            try WorkStage(id: id, directory: URL(fileURLWithPath: path), registry: file).cleanup()
        }
    }
}
