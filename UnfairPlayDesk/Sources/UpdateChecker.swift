import Foundation
import Combine

@MainActor final class UpdateChecker: ObservableObject {
    nonisolated static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    }
    static let releaseURL = URL(string: "https://github.com/Emokui/UnfairPlay/releases/latest")!
    @Published private(set) var available: String?
    @Published private(set) var checking = false
    @Published private(set) var message: String?
    private var checkedAutomatically = false

    func check(manual: Bool = false) async {
        guard !checking, manual || !checkedAutomatically else { return }
        checkedAutomatically = true
        checking = true
        message = nil
        defer { checking = false }
        do {
            var request = URLRequest(url: URL(string: "https://api.github.com/repos/Emokui/UnfairPlay/releases/latest")!)
            request.timeoutInterval = 15
            request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            request.setValue("UnfairPlay/\(Self.currentVersion)", forHTTPHeaderField: "User-Agent")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                throw DeskError("暂时无法获取更新，请稍后重试。")
            }
            struct Release: Decodable {
                let tag: String
                let draft: Bool
                let prerelease: Bool
                enum CodingKeys: String, CodingKey { case tag = "tag_name", draft, prerelease }
            }
            let release = try JSONDecoder().decode(Release.self, from: data)
            guard !release.draft, !release.prerelease else { return }
            available = Self.isNewer(release.tag, than: Self.currentVersion) ? release.tag : nil
        } catch {
            if !Task.isCancelled { message = "检查更新失败，请检查网络后重试。" }
        }
    }

    static func isNewer(_ candidate: String, than current: String) -> Bool {
        func parse(_ version: String) -> (numbers: [Int], prerelease: Bool)? {
            var text = version.trimmingCharacters(in: .whitespacesAndNewlines)
            if text.hasPrefix("v") || text.hasPrefix("V") { text.removeFirst() }
            guard let core = text.split(separator: "+", maxSplits: 1).first else { return nil }
            let parts = core.split(separator: "-", maxSplits: 1)
            guard let base = parts.first else { return nil }
            let components = base.split(separator: ".", omittingEmptySubsequences: false)
            let numbers = components.compactMap { Int($0) }
            guard components.count == 3, numbers.count == 3, numbers.allSatisfy({ $0 >= 0 }) else { return nil }
            return (numbers, parts.count == 2)
        }
        guard let remote = parse(candidate), let local = parse(current) else { return false }
        if remote.numbers != local.numbers { return local.numbers.lexicographicallyPrecedes(remote.numbers) }
        return local.prerelease && !remote.prerelease
    }
}
