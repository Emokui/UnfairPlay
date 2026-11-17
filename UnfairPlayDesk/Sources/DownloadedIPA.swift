import Foundation

struct DownloadedIPA: Codable, Identifiable {
    let url: URL
    let appName: String
    var id: String { url.standardizedFileURL.path }

    private static let key = "savedIPADownloads"

    static func load() -> [Self] {
        guard let data = UserDefaults.standard.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode([Self].self, from: data)) ?? []
    }

    static func save(_ entries: [Self]) {
        if let data = try? JSONEncoder().encode(entries) { UserDefaults.standard.set(data, forKey: key) }
    }

    static func filename(for appName: String, noUpdate: Bool) -> String {
        let invalid = CharacterSet(charactersIn: "/:").union(.controlCharacters)
        let stem = appName.components(separatedBy: invalid).joined(separator: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines.union(CharacterSet(charactersIn: ".")))
        return (stem.isEmpty ? "应用" : stem) + (noUpdate ? "_no-update.ipa" : ".ipa")
    }
}
