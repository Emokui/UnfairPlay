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
    struct FileStamp: Equatable, Codable {
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
    static func isMissingFile(_ url: URL) -> Bool {
        var info = stat()
        if fstatat(AT_FDCWD, url.path, &info, 0) == 0 {
            return info.st_mode & S_IFMT != S_IFREG
        }
        // Keep references when macOS denies access instead of reporting a missing file.
        return errno == ENOENT || errno == ENOTDIR
    }
    static func recycleIPAs(_ files: [URL]) -> (removed: Set<String>, failures: [String]) {
        var removed = Set<String>()
        var failures: [String] = []
        for file in files {
            if !isMissingFile(file) {
                do { try FileManager.default.trashItem(at: file, resultingItemURL: nil) }
                catch {
                    if !isMissingFile(file) {
                        failures.append("\(file.lastPathComponent) — \(error.localizedDescription)")
                        continue
                    }
                }
            }
            removed.insert(file.standardizedFileURL.path)
        }
        return (removed, failures)
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
    static func storeFront(in output: String) -> String? {
        for line in output.components(separatedBy: .newlines).reversed() {
            guard let start = line.firstIndex(of: "{"), let data = String(line[start...]).data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  json["success"] as? Bool == true || json["sessionRefreshed"] as? Bool == true, json["email"] is String,
                  let value = json["storeFront"] as? String else { continue }
            return value
        }
        return nil
    }
    static func refreshedSession(in output: String) -> (email: String, storeFront: String?)? {
        for line in output.components(separatedBy: .newlines).reversed() {
            guard let start = line.firstIndex(of: "{"), let data = String(line[start...]).data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  json["sessionRefreshed"] as? Bool == true,
                  let email = (json["email"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                  !email.isEmpty else { continue }
            return (email, json["storeFront"] as? String)
        }
        return nil
    }
    static func operationError(title: String, hint: String?, output: String) -> String {
        let detail = output.components(separatedBy: .newlines).reversed().lazy.compactMap { line -> String? in
            if let start = line.firstIndex(of: "{"),
               let json = try? JSONSerialization.jsonObject(with: Data(line[start...].utf8)) as? [String: Any],
               let error = json["error"] as? String { return error }
            let text = line.trimmingCharacters(in: .whitespaces)
            return text.lowercased().hasPrefix("error:") ? String(text.dropFirst(6)).trimmingCharacters(in: .whitespaces) : nil
        }.first
        return [title + "：未完成", hint, detail.map { String($0.prefix(650)) }]
            .compactMap { $0 }.joined(separator: "\n\n")
    }
    static func isMissingSession(in lowercaseError: String) -> Bool {
        (lowercaseError.contains("keyring") || lowercaseError.contains("failed to get account")) &&
            (lowercaseError.contains("not be found") || lowercaseError.contains("not found") || lowercaseError.contains("no such file"))
    }
    static func errorHint(_ text: String) -> String {
        let value = text.lowercased()
        if value.contains("read macos keychain item") { return "钥匙串读取未获授权，请在系统弹窗中允许访问后重试。" }
        if value.contains("encrypted account session") || value.contains("account session key is") {
            return "此账户的加密会话或密钥不可用，请在账户菜单清除此账户登陆，再重新登录。"
        }
        if value.contains("account session was cleared") { return "此账户的登录信息已清除，请重新登录。" }
        if value.contains("free app license rejected after sign-in refresh") { return "Apple 在重新验证后仍未发放免费许可。请先用同一个 Apple ID 在 App Store 点「获取」，再回来下载。" }
        if value.contains("unsupported") && (value.contains("build") || value.contains("fairplay")) { return "当前系统构建暂未受内置工具支持，请升级工具后再初始化；不要放宽校验或强行生成模型。" }
        if value.contains("license is required") { return "当前 ID 尚未取得此应用许可。若自动获取未成功，请用此 ID 在 App Store 获取或购买应用后重试，无需清除登录。" }
        if value.contains("deadline exceeded") || value.contains("client.timeout") || value.contains("i/o timeout") { return "Apple 接口响应超时，请重试。" }
        if value.contains("download received no data") { return "下载连接长时间没有收到数据，续传仍未成功，请重试。" }
        if value.contains("download account does not match") || value.contains("account does not match selected profile") { return "下载会话与所选账户不一致，请在账户操作菜单重新登录。" }
        if value.contains("incorrect apple account or password") { return "Apple 拒绝了账号或密码，请核对后重试。" }
        if value.contains("apple did not confirm sign-in") { return "请核对 Apple 账户和密码。收到本次登录的验证码后，可以选择继续验证。" }
        if value.contains("apple did not accept the password and verification code") { return "请核对密码和本次登录的六位验证码，再重新登录。" }
        if value.contains("auth code is required") { return "Apple 要求重新验证，请在账户操作菜单选择继续登录。" }
        if value.contains("store amd state is not provisioned") || value.contains("returned no store amd proof") { return "当前账户缺少商店设备认证信息，请在账户操作菜单选择继续登录。" }
        if value.contains("password token") || value.contains("token expired") || value.contains("session expired") || value.contains("failed to refresh apple login") { return "登录会话已过期，请在账户操作菜单选择继续登录。" }
        if isMissingSession(in: value) { return "这个账户档案尚未登录，请先登录此 ID。" }
        if value.contains("keychain passphrase") { return "需要解锁此账户的加密凭据库。请按提示输入解锁口令，它与 Apple ID 密码不同。" }
        if value.contains("authcode") || value.contains("2fa") || value.contains("verification") { return "需要验证 Apple 账户，请按提示输入验证码；若操作已结束，请重新登录。" }
        if value.contains("permission denied") || value.contains("operation not permitted") { return "文件或授权状态不可读取。请检查文件所有者、私有权限，以及系统授权是否完成。" }
        if value.contains("selector") || value.contains("enrollment") && value.contains("match") { return "IPA 与所选模型的账户授权状态不匹配，请选择对应账户的模型和 IPA。" }
        if value.contains("model") { return "模型缺失、无效或与 IPA 不匹配，请查看模型状态并重新校验、导入或初始化。" }
        if value.contains("authorization") || value.contains("授权") { return "管理员授权未完成，请重试初始化；取消授权不会生成新模型。" }
        return "请检查所选文件或账户后重试。"
    }
    static func isFilePermissionError(_ error: Error) -> Bool {
        let cause = error as NSError
        if cause.domain == NSPOSIXErrorDomain { return cause.code == Int(EPERM) || cause.code == Int(EACCES) }
        if cause.domain == NSCocoaErrorDomain && cause.code == NSFileReadNoPermissionError { return true }
        if let underlying = cause.userInfo[NSUnderlyingErrorKey] as? Error {
            return isFilePermissionError(underlying)
        }
        return false
    }
}
