import Foundation
import CryptoKit
import Darwin

struct IPADecryptionReport: Decodable {
    struct File: Decodable { let path: String; let sha256: String? }
    struct Audit: Decodable {
        let slot_count: Int
        let matched_slots: Int
    }
    struct ImageAudit: Decodable {
        let member: String
        let architecture: String?
        let first_page_audit: String?
        let pages: Int?
        let code_directories: [Audit]?
        let pre_encryption_code_directories: [Audit]?
        var auditDescription: String {
            switch first_page_audit {
            case "code-directory-pre-encryption-hashes": "明文页哈希验证"
            case "arm64-instruction-decode": "ARM64 指令结构审计"
            case "arm64-first-executable-page-instruction-decode": "ARM64 首个可执行页结构审计"
            case "not-performed": "未执行独立明文审核"
            default: first_page_audit ?? "未记录审核方式"
            }
        }
    }
    let input: File
    let output: File
    let encrypted_image_count: Int?
    let decrypted_page_count: Int?
    let plaintext_verified: Bool?
    let complete: Bool?
    let signature_verified: Bool?
    let images: [ImageAudit]?
    let warnings: [String]?
}

struct IPASavedReport: Identifiable {
    let url: URL
    let document: IPADecryptionReport
    var id: URL { url }

    static func find(for file: URL, root: URL) throws -> Self {
        let digest = try sha256Hex(of: file)
        let targetStandardized = file.standardizedFileURL
        let targetCanonical = Core.canonicalSystemPath(file.resolvingSymlinksInPath().standardizedFileURL.path)
        let directory = root.appendingPathComponent("Reports")
        let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey, .contentModificationDateKey]
        let enumerator = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles])
        var newest: (report: Self, date: Date)?
        var newestByDigestOnly: (report: Self, date: Date, isOutput: Bool)?
        var hadDigestMismatchAtSamePath = false
        while let url = enumerator?.nextObject() as? URL {
            guard url.pathExtension == "json",
                  let values = try? url.resourceValues(forKeys: Set(keys)),
                  values.isRegularFile == true,
                  values.isSymbolicLink != true,
                  let bytes = try? Data(contentsOf: url),
                  let document = try? JSONDecoder().decode(IPADecryptionReport.self, from: bytes) else { continue }
            let inputSHA = nonEmptyLowercased(document.input.sha256)
            let outputSHA = nonEmptyLowercased(document.output.sha256)
            let matchesInputPath = matchesPath(document.input.path, standardized: targetStandardized, canonical: targetCanonical)
            let matchesOutputPath = matchesPath(document.output.path, standardized: targetStandardized, canonical: targetCanonical)
            let date = values.contentModificationDate ?? .distantPast
            if matchesInputPath || matchesOutputPath {
                let inputDigestMatch = matchesInputPath && inputSHA == digest
                let outputDigestMatch = matchesOutputPath && outputSHA == digest
                guard inputDigestMatch || outputDigestMatch else {
                    hadDigestMismatchAtSamePath = true
                    continue
                }
                if newest == nil || date > newest!.date { newest = (Self(url: url, document: document), date) }
            } else if outputSHA == digest || inputSHA == digest {
                let isOutput = outputSHA == digest
                if let current = newestByDigestOnly {
                    if (isOutput && !current.isOutput) || (isOutput == current.isOutput && date > current.date) {
                        newestByDigestOnly = (Self(url: url, document: document), date, isOutput)
                    }
                } else {
                    newestByDigestOnly = (Self(url: url, document: document), date, isOutput)
                }
            }
        }
        if let newest { return newest.report }
        if hadDigestMismatchAtSamePath {
            throw DeskError("尚未找到与当前 IPA 内容匹配的解密报告。文件可能已被替换，重新解密并保存后可在此查看。")
        }
        if let newestByDigestOnly { return newestByDigestOnly.report }
        throw DeskError("尚未找到这个 IPA 的解密报告。使用本软件解密并保存后可在此查看。")
    }

    private static func nonEmptyLowercased(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !trimmed.isEmpty else {
            return nil
        }
        return trimmed
    }

    private static func matchesPath(_ path: String, standardized: URL, canonical: String) -> Bool {
        let candidate = URL(fileURLWithPath: path)
        if candidate.standardizedFileURL == standardized { return true }
        return Core.canonicalSystemPath(candidate.resolvingSymlinksInPath().standardizedFileURL.path) == canonical
    }

    private static func sha256Hex(of url: URL) throws -> String {
        let resolved = url.resolvingSymlinksInPath()
        let fd = open(resolved.path, O_RDONLY | O_NONBLOCK)
        guard fd >= 0 else {
            throw DeskError("所选 IPA 文件不存在或无法读取，无法核对解密报告。")
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw DeskError("所选 IPA 文件不存在或不是普通文件，无法核对解密报告。")
        }
        let flags = fcntl(fd, F_GETFL)
        if flags >= 0 { _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) }
        var hasher = SHA256()
        let bufferSize = 262_144
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        while true {
            let count = read(fd, buffer, bufferSize)
            if count > 0 {
                hasher.update(bufferPointer: UnsafeRawBufferPointer(start: buffer, count: count))
            } else if count == 0 {
                break
            } else if errno != EINTR {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
