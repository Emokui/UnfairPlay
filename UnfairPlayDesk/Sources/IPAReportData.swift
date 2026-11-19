import Foundation

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
        let directory = root.appendingPathComponent("Reports")
        let keys: [URLResourceKey] = [.isRegularFileKey, .contentModificationDateKey]
        let enumerator = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles])
        var newest: (report: Self, date: Date)?
        while let url = enumerator?.nextObject() as? URL {
            guard url.pathExtension == "json", let values = try? url.resourceValues(forKeys: Set(keys)), values.isRegularFile == true,
                  let bytes = try? Data(contentsOf: url), let document = try? JSONDecoder().decode(IPADecryptionReport.self, from: bytes) else { continue }
            let paths = [document.input.path, document.output.path].map { URL(fileURLWithPath: $0).standardizedFileURL }
            guard paths.contains(file.standardizedFileURL) else { continue }
            let date = values.contentModificationDate ?? .distantPast
            if newest == nil || date > newest!.date { newest = (Self(url: url, document: document), date) }
        }
        guard let newest else { throw DeskError("尚未找到这个 IPA 的解密报告。使用本软件解密并保存后可在此查看。") }
        return newest.report
    }
}
