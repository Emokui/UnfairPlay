import Foundation

struct DownloadedIPA: Codable, Identifiable {
    let url: URL
    let appName: String
    var accountID: UUID?
    var appID: String?
    var version: String?
    var bundleID: String?
    var stamp: Core.FileStamp?
    var id: String { url.standardizedFileURL.path }

    private static let key = "savedIPADownloads"

    static func load() -> [Self] {
        guard let data = UserDefaults.standard.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode([Self].self, from: data)) ?? []
    }

    static func save(_ entries: [Self]) {
        if let data = try? JSONEncoder().encode(entries) { UserDefaults.standard.set(data, forKey: key) }
    }

    static func versionForFilename(_ version: String?, versionID: String) -> String? {
        if let value = version?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty, value != "未知版本" {
            return value
        }
        return versionID.isEmpty ? nil : "版本ID-" + versionID
    }

    static func filename(for appName: String, noUpdate: Bool, version: String? = nil) -> String {
        let invalid = CharacterSet(charactersIn: "/:").union(.controlCharacters)
        func cleaned(_ value: String) -> String {
            value.components(separatedBy: invalid).joined(separator: " ")
                .trimmingCharacters(in: .whitespacesAndNewlines.union(CharacterSet(charactersIn: ".")))
        }
        let stem = cleaned(appName)
        let suffix = version.map(cleaned).flatMap { $0.isEmpty ? nil : "_" + $0 } ?? ""
        return (stem.isEmpty ? "应用" : stem) + suffix + (noUpdate ? "_no-update.ipa" : ".ipa")
    }

    static func unusedTarget(named filename: String, in directory: URL) throws -> Core.OutputTarget {
        let name = (filename as NSString).deletingPathExtension
        let ext = (filename as NSString).pathExtension
        var number = 1
        while true {
            let suffix = number == 1 ? "" : "-\(number)"
            let candidate = directory.appendingPathComponent(name + suffix).appendingPathExtension(ext)
            let target = try Core.OutputTarget(candidate)
            if target.original == nil { return target }
            number += 1
        }
    }
}
