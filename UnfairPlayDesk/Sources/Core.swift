import Foundation
import CryptoKit
import Darwin
import Security

struct DeskError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}

enum Core {
    // Share one background check across foreground tools and model diagnostics.
    static let bundleVerification = Task.detached(priority: .userInitiated) { try verifyBundle() }
    struct FileStamp: Equatable {
        let device: dev_t, inode: ino_t, size: off_t, mode: mode_t
        let modifiedSeconds: Int, modifiedNanos: Int, changedSeconds: Int, changedNanos: Int
    }
    static func fileStamp(_ url: URL) throws -> FileStamp? {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            if errno == ENOENT { return nil }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return FileStamp(device: info.st_dev, inode: info.st_ino, size: info.st_size, mode: info.st_mode,
                         modifiedSeconds: info.st_mtimespec.tv_sec, modifiedNanos: info.st_mtimespec.tv_nsec,
                         changedSeconds: info.st_ctimespec.tv_sec, changedNanos: info.st_ctimespec.tv_nsec)
    }
    struct OutputTarget {
        let url: URL
        let original: FileStamp?
        init(_ url: URL) throws { self.url = url; original = try Core.fileStamp(url) }
        func commit(_ temporary: URL, protecting input: URL? = nil) throws {
            guard try Core.fileStamp(url) == original else { throw DeskError("保存位置的文件在任务期间发生变化，请重新选择输出位置。") }
            try Core.commit(temporary, to: url, protecting: input, exclusive: original == nil)
        }
    }
    static func modelStamp(_ directory: URL) throws -> [String: FileStamp] {
        var result: [String: FileStamp] = [:]
        result["."] = try fileStamp(directory)
        for file in try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) where file.pathExtension.lowercased() == "bin" {
            result[file.lastPathComponent] = try fileStamp(file)
        }
        return result
    }
    static func verifyBundle() throws {
        #if !DESK_TESTING
        var code: SecStaticCode?
        let result = SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code)
        guard result == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode), nil) == errSecSuccess else {
            throw DeskError("软件或内置工具签名校验失败，请使用完整的软件包重新安装。")
        }
        #endif
    }
    static func appID(_ value: String) -> String? {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if !text.isEmpty && text.allSatisfy(\.isASCII) && text.allSatisfy(\.isNumber), let n = Int64(text), n > 0 { return text }
        guard let url = URL(string: text), url.scheme == "https", url.host == "apps.apple.com",
              let part = url.path.split(separator: "/").last, part.hasPrefix("id") else { return nil }
        return appID(String(part.dropFirst(2)))
    }
    static func privateDirectory(_ url: URL) throws {
        if try fileStamp(url) != nil { try ordinaryDirectory(url) }
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }
    static func canonicalSystemPath(_ path: String) -> String {
        if path.hasPrefix("/var/") || path.hasPrefix("/tmp/") { return "/private" + path }
        return path
    }
    static func ordinaryDirectory(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true, values.isSymbolicLink != true,
              canonicalSystemPath(url.standardizedFileURL.path) == canonicalSystemPath(url.resolvingSymlinksInPath().standardizedFileURL.path) else {
            throw DeskError("数据目录包含符号链接或不是普通文件夹，已停止操作。")
        }
    }
    static func writeJSON(_ value: Any, to url: URL) throws {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
    static func sameFile(_ a: URL, _ b: URL) -> Bool {
        if a.resolvingSymlinksInPath().standardizedFileURL == b.resolvingSymlinksInPath().standardizedFileURL { return true }
        guard let x = try? FileManager.default.attributesOfItem(atPath: a.path),
              let y = try? FileManager.default.attributesOfItem(atPath: b.path),
              let inodeA = x[.systemFileNumber] as? NSNumber, let inodeB = y[.systemFileNumber] as? NSNumber,
              let deviceA = x[.systemNumber] as? NSNumber, let deviceB = y[.systemNumber] as? NSNumber else { return false }
        return inodeA == inodeB && deviceA == deviceB
    }
    static func commit(_ temporary: URL, to target: URL, protecting input: URL? = nil, exclusive: Bool = false) throws {
        if let input, sameFile(input, target) { throw DeskError("输出位置与原始 IPA 实际上是同一个文件，已停止保存。") }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: temporary.path)
        // rename preserves the private metadata of the new file, including when replacing a 0644 file.
        let result = temporary.path.withCString { source in target.path.withCString { destination in exclusive ? renamex_np(source, destination, UInt32(RENAME_EXCL)) : Darwin.rename(source, destination) } }
        if result != 0 {
            guard errno == EXDEV else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            let local = target.deletingLastPathComponent().appendingPathComponent(".unfairplay-save-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: local) }
            try FileManager.default.copyItem(at: temporary, to: local)
            try commit(local, to: target, protecting: input, exclusive: exclusive)
            try? FileManager.default.removeItem(at: temporary)
        }
    }
    static func modelFiles(_ url: URL, requirePrivatePermissions: Bool = true) throws -> [URL] {
        guard FileManager.default.fileExists(atPath: url.path) else { throw DeskError("当前档案尚未初始化模型，请先初始化或导入模型。") }
        try ordinaryDirectory(url)
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard !requirePrivatePermissions || ((attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0o777) & 0o077 == 0 else { throw DeskError("模型目录权限过宽，请使用仅当前用户可访问的目录。") }
        let files = try FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey]).filter { $0.pathExtension.lowercased() == "bin" }
        guard !files.isEmpty else { throw DeskError("尚未添加模型，请导入或初始化。") }
        guard files.count <= 256 else { throw DeskError("模型文件超过 256 个，请减少后重试。") }
        for file in files {
            let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true, FileManager.default.isReadableFile(atPath: file.path) else { throw DeskError("模型不是可读的普通文件，请检查文件所有权和权限。") }
            let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
            guard !requirePrivatePermissions || ((attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0o777) & 0o077 == 0 else { throw DeskError("模型文件权限过宽，应为 600。") }
            guard let size = attrs[.size] as? NSNumber, size.intValue >= 16, size.intValue < 16_777_216 else { throw DeskError("模型文件大小异常。") }
            let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
            let header = try handle.read(upToCount: 16) ?? Data()
            guard header.count == 16, (Array(header.prefix(6)) == Array("FPSENR".utf8) && [UInt8(49), UInt8(50), UInt8(51)].contains(header[6]) || Array(header.prefix(8)) == Array("FPS26A4\0".utf8)), header[7] == 0 else { throw DeskError("模型格式无效或版本不受支持。") }
            let version = header[8..<12].enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << ($1.offset * 8) }
            let length = header[12..<16].enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << ($1.offset * 8) }
            guard [1, 2, 3].contains(version), Int(length) == size.intValue else { throw DeskError("模型已截断或版本不受支持。") }
        }
        return files
    }
    static func hasModel(_ url: URL) -> Bool { (try? modelFiles(url)) != nil }
    static func installModels(_ source: URL, to dest: URL) throws {
        let files = try modelFiles(source)
        try privateDirectory(dest)
        for file in files {
            let target = dest.appendingPathComponent(file.lastPathComponent)
            let temporary = dest.appendingPathComponent(".import-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: temporary) }
            try FileManager.default.copyItem(at: file, to: temporary)
            try commit(temporary, to: target)
        }
    }
    static func modelHashes(in directory: URL) throws -> Set<String> {
        guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
        try ordinaryDirectory(directory)
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        var hashes: Set<String> = []
        for file in files where file.pathExtension.lowercased() == "bin" {
            let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true, (values.fileSize ?? Int.max) <= 16_777_216 else { throw DeskError("旧报告关联遇到异常模型文件，已停止清理。") }
            hashes.insert(SHA256.hash(data: try Data(contentsOf: file)).map { String(format: "%02x", $0) }.joined())
        }
        return hashes
    }
    static func associateLegacyReports(_ id: UUID, root: URL) throws {
        let reports = root.appendingPathComponent("Reports")
        guard FileManager.default.fileExists(atPath: reports.path) else { return }
        try ordinaryDirectory(reports)
        let legacy = try FileManager.default.contentsOfDirectory(at: reports, includingPropertiesForKeys: [.isSymbolicLinkKey]).filter { $0.pathExtension == "json" }
        guard !legacy.isEmpty else { return }
        let modelRoot = root.appendingPathComponent("Models")
        if FileManager.default.fileExists(atPath: modelRoot.path) { try ordinaryDirectory(modelRoot) }
        let own = try modelHashes(in: modelRoot.appendingPathComponent(id.uuidString))
        let siblings = FileManager.default.fileExists(atPath: modelRoot.path) ? try FileManager.default.contentsOfDirectory(at: modelRoot, includingPropertiesForKeys: nil) : []
        let others = try siblings.filter { UUID(uuidString: $0.lastPathComponent) != nil && $0.lastPathComponent.lowercased() != id.uuidString.lowercased() }.reduce(into: Set<String>()) { $0.formUnion(try modelHashes(in: $1)) }
        let unique = own.subtracting(others)
        for report in legacy {
            guard try report.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true else { throw DeskError("报告文件包含符号链接，已停止清理。") }
            guard let json = try JSONSerialization.jsonObject(with: Data(contentsOf: report)) as? [String: Any] else { throw DeskError("旧报告格式损坏，请先检查报告目录。") }
            let explicit = (json["account_profile_id"] as? String).flatMap(UUID.init(uuidString:))
            let digest = ((json["oracle"] as? [String: Any])?["model_sha256"] as? String)?.lowercased()
            guard explicit == id || (explicit == nil && digest.map(unique.contains) == true) else { continue }
            let dest = reports.appendingPathComponent(id.uuidString)
            try privateDirectory(dest)
            var marked = json; marked["account_profile_id"] = id.uuidString
            let target = dest.appendingPathComponent(report.lastPathComponent)
            if FileManager.default.fileExists(atPath: target.path) { throw DeskError("旧报告迁移遇到同名文件，已保留两份报告并停止操作。") }
            try writeJSON(marked, to: target)
            try FileManager.default.removeItem(at: report)
        }
    }
    @discardableResult
    static func recycleModels(in directory: URL, recycle: (URL) throws -> Void = { try FileManager.default.trashItem(at: $0, resultingItemURL: nil) }) throws -> Bool {
        guard FileManager.default.fileExists(atPath: directory.path) else { return false }
        try ordinaryDirectory(directory)
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        guard files.contains(where: { $0.pathExtension.lowercased() == "bin" }) else { return false }
        if let id = UUID(uuidString: directory.lastPathComponent) { try associateLegacyReports(id, root: directory.deletingLastPathComponent().deletingLastPathComponent()) }
        try recycle(directory); try privateDirectory(directory); return true
    }
    static func removeAccountData(_ id: UUID, root: URL) throws {
        try ordinaryDirectory(root)
        for name in ["Models", "Sessions", "Reports"] {
            let parent = root.appendingPathComponent(name)
            if try fileStamp(parent) != nil { try ordinaryDirectory(parent) }
            let directory = parent.appendingPathComponent(name == "Sessions" ? id.uuidString.lowercased() : id.uuidString)
            if try fileStamp(directory) != nil { try ordinaryDirectory(directory) }
        }
        try associateLegacyReports(id, root: root)
        try WorkStage.removeAccountJobs(id, root: root)
        for name in ["Sessions", "Reports", "Models"] {
            let directory = root.appendingPathComponent("\(name)/\(name == "Sessions" ? id.uuidString.lowercased() : id.uuidString)")
            if FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
        }
    }
    static func finalizeReport(_ report: URL, output: URL, accountID: UUID) throws {
        guard var json = try JSONSerialization.jsonObject(with: Data(contentsOf: report)) as? [String: Any], var item = json["output"] as? [String: Any] else { throw DeskError("解密报告缺少输出记录。") }
        item["path"] = output.path; json["output"] = item; json["account_profile_id"] = accountID.uuidString
        try writeJSON(json, to: report)
    }
    static func email(in output: String) -> String? {
        for line in output.components(separatedBy: .newlines).reversed() {
            guard let start = line.firstIndex(of: "{"), let data = String(line[start...]).data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any], json["success"] as? Bool == true,
                  let email = json["email"] as? String else { continue }
            return email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        return nil
    }
    static func errorHint(_ text: String) -> String {
        let value = text.lowercased()
        if value.contains("unsupported") && (value.contains("build") || value.contains("fairplay")) { return "当前系统构建暂未受内置工具支持，请升级工具后再初始化；不要放宽校验或强行生成模型。" }
        if value.contains("license is required") { return "当前 ID 尚未取得此应用许可。若自动获取未成功，请用此 ID 在 App Store 获取或购买应用后重试，无需清除登录。" }
        if value.contains("password token") || value.contains("token expired") || value.contains("session expired") { return "登录会话已过期，请清除此账户登陆后重新登录。" }
        if (value.contains("keyring") || value.contains("failed to get account")) && (value.contains("not be found") || value.contains("not found") || value.contains("no such file")) { return "这个账户档案尚未登录，请先登录此 ID。" }
        if value.contains("keychain passphrase") { return "需要解锁此账户的加密凭据库。请按提示输入解锁口令，它与 Apple ID 密码不同。" }
        if value.contains("authcode") || value.contains("2fa") || value.contains("verification") { return "需要验证 Apple 账户，请按提示输入验证码；若操作已结束，请重新登录。" }
        if value.contains("permission denied") || value.contains("operation not permitted") { return "文件或授权状态不可读取。请检查文件所有者、私有权限，以及系统授权是否完成。" }
        if value.contains("selector") || value.contains("enrollment") && value.contains("match") { return "IPA 与所选模型的账户授权状态不匹配，请选择对应账户的模型和 IPA。" }
        if value.contains("model") { return "模型缺失、无效或与 IPA 不匹配，请查看模型状态并重新校验、导入或初始化。" }
        if value.contains("authorization") || value.contains("授权") { return "管理员授权未完成，请重试初始化；取消授权不会生成新模型。" }
        return "操作未完成，请查看下方具体错误后重试。"
    }
}
