import Foundation
import Combine

struct CatalogApp: Decodable, Identifiable {
    let id: Int64
    let name: String
    let bundleID: String
    let version: String?
    let artist: String?
    let artwork: URL?
    private let price: Double?
    private let formattedPrice: String?
    private let currency: String?
    private let fileSizeBytes: Int64?
    enum CodingKeys: String, CodingKey {
        case id = "trackId", name = "trackName", bundleID = "bundleId", version
        case artist = "artistName", artwork = "artworkUrl100", fileSizeBytes, price, formattedPrice, currency
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(Int64.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        bundleID = try values.decode(String.self, forKey: .bundleID)
        version = try values.decodeIfPresent(String.self, forKey: .version)
        artist = try values.decodeIfPresent(String.self, forKey: .artist)
        artwork = try values.decodeIfPresent(URL.self, forKey: .artwork)
        price = try? values.decode(Double.self, forKey: .price)
        formattedPrice = try? values.decode(String.self, forKey: .formattedPrice)
        currency = try? values.decode(String.self, forKey: .currency)
        let sizeString = try? values.decode(String.self, forKey: .fileSizeBytes)
        fileSizeBytes = sizeString.flatMap(Int64.init) ?? (try? values.decode(Int64.self, forKey: .fileSizeBytes))
    }
    var sizeText: String? {
        guard let fileSizeBytes, fileSizeBytes > 0 else { return nil }
        return ByteCountFormatter.string(fromByteCount: fileSizeBytes, countStyle: .file)
    }
    var priceText: String? {
        guard let price, price > 0 else { return nil }
        if let formattedPrice, !formattedPrice.isEmpty { return formattedPrice }
        if let currency, !currency.isEmpty { return price.formatted(.currency(code: currency)) }
        return price.formatted()
    }
}

struct CatalogVersion: Decodable {
    let externalVersionID: String
    let displayVersion: String
    let releaseDate: String?
    var dateText: String? {
        guard let releaseDate else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions.insert(.withFractionalSeconds)
        let date = formatter.date(from: releaseDate) ?? ISO8601DateFormatter().date(from: releaseDate)
        guard let date, date.timeIntervalSince1970 > 0 else { return nil }
        return date.formatted(date: .abbreviated, time: .omitted)
    }
}

enum VersionSource: String, CaseIterable, Identifiable {
    case timbrd = "Timbrd", bilin = "Bilin", iosdump = "iOSDump"
    var id: String { rawValue }
}

struct CatalogHistoryVersion: Identifiable {
    let id: String
    let version: String
    let date: String
}

enum CatalogPurchaseStatus: Equatable {
    case owned, unowned

    var text: String {
        switch self {
        case .owned: "已购买"
        case .unowned: "未购买"
        }
    }
}

@MainActor final class DownloadCatalog: ObservableObject {
    @Published var apps: [CatalogApp] = []
    @Published var searched = false
    @Published var country = "US"
    @Published var source: VersionSource = .timbrd
    @Published var busy = false
    @Published var error: String?
    @Published var appID: String?
    @Published var versions: [CatalogHistoryVersion] = []
    @Published var versionsLoaded = false
    @Published var selectedVersion = ""
    @Published var details: [String: CatalogVersion] = [:]
    @Published var metadataError: String?
    @Published var purchaseStatus: [String: CatalogPurchaseStatus] = [:]
    @Published private var directLookup: (id: String, country: String, app: CatalogApp?)?
    private var task: Task<Void, Never>?
    private var generation = UUID()
    private var usesManualCountry = false

    func cancel() {
        task?.cancel(); task = nil; generation = UUID(); busy = false
    }
    func clearSearchResults() {
        cancel()
        discardSearchResults()
        error = nil
    }
    private func discardSearchResults() {
        apps = []
        searched = false
        directLookup = nil
    }
    func selectApp(_ id: String?) {
        guard appID != id else { return }
        cancel(); appID = id; clearVersions()
    }
    func clearVersions() {
        versions = []; versionsLoaded = false; error = nil
        clearAccountVersionSelection()
    }
    private func clearAccountVersionSelection() {
        selectedVersion = ""; details = [:]; metadataError = nil
    }
    func changeAccount() {
        usesManualCountry = false
        purchaseStatus = [:]
        clearAccountVersionSelection()
    }
    func selectCountry(_ code: String) {
        usesManualCountry = true
        setCountry(code)
    }
    func updateAccountCountry(_ storeFront: String?, afterLogin: Bool = false) {
        if afterLogin { usesManualCountry = false }
        if !usesManualCountry { setCountry(Self.country(forStoreFront: storeFront)) }
    }
    private func setCountry(_ code: String) {
        guard code != country else { return }
        if appID == nil { clearSearchResults() }
        else { discardSearchResults() }
        country = code
    }
    var versionArguments: [String] {
        selectedVersion.isEmpty ? [] : ["--external-version-id", selectedVersion]
    }
    var validVersion: Bool {
        selectedVersion.isEmpty || Self.numericID(selectedVersion)
    }
    func app(for id: String) -> CatalogApp? {
        apps.first { String($0.id) == id } ?? completedLookup(for: id)?.app
    }
    func isWaitingForAppName(_ id: String) -> Bool {
        app(for: id) == nil && completedLookup(for: id) == nil
    }
    private func completedLookup(for id: String) -> (id: String, country: String, app: CatalogApp?)? {
        guard let directLookup, directLookup.id == id, directLookup.country == country else { return nil }
        return directLookup
    }
    func lookUpAppName(_ id: String) async {
        guard isWaitingForAppName(id) else { return }
        let region = country
        let matches = try? await CatalogService.search(id, country: region, timeout: 5)
        guard !Task.isCancelled, appID == id, country == region else { return }
        directLookup = (id, region, matches?.first)
    }
    nonisolated static func country(forStoreFront storeFront: String?) -> String {
        StorefrontRegions.defaultCountry(for: storeFront)
    }
    nonisolated static func numericID(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { (48...57).contains($0) } && UInt64(value).map { $0 > 0 } == true
    }

    func search(_ query: String) {
        cancel(); error = nil; searched = false; apps = []; busy = true
        let token = generation, country = country
        task = Task {
            do {
                let matches = try await CatalogService.search(query, country: country)
                guard generation == token else { return }
                apps = matches; searched = true; busy = false; task = nil
            } catch {
                guard generation == token else { return }
                busy = false; task = nil
                if !Task.isCancelled { self.error = error.localizedDescription }
            }
        }
    }
    func loadPublicHistory() {
        guard let appID else { return }
        cancel(); error = nil; busy = true
        let token = generation, source = source
        task = Task {
            do {
                let records = try await CatalogService.history(appID, source: source)
                guard generation == token else { return }
                versions = records; versionsLoaded = true; busy = false; task = nil
            } catch {
                guard generation == token else { return }
                busy = false; task = nil
                if !Task.isCancelled { self.error = error.localizedDescription }
            }
        }
    }
    // CLI logs contain one JSON object per line, interleaved with progress text.
    static func response<T: Decodable>(_ type: T.Type, in output: String) throws -> T {
        for line in output.split(whereSeparator: \.isNewline).reversed() {
            if let value = try? JSONDecoder().decode(type, from: Data(line.utf8)) { return value }
        }
        throw DeskError("未能读取应用查询结果，请重试。")
    }
}

// Public catalogs receive only the search term, region or App ID. Authentication
// and package downloads remain in the existing per-account ipatool process.
enum CatalogService {
    static func request(_ url: URL, timeout: TimeInterval = 20) async throws -> Data {
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("UnfairPlay/\(UpdateChecker.currentVersion)", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw DeskError("查询服务未返回有效响应。") }
        guard (200..<300).contains(http.statusCode) else {
            throw DeskError("查询服务返回 HTTP \(http.statusCode)，请稍后重试或切换来源。")
        }
        return data
    }
    static func search(_ term: String, country: String, timeout: TimeInterval = 20) async throws -> [CatalogApp] {
        let query = term.trimmingCharacters(in: .whitespacesAndNewlines)
        let id = Core.appID(query)
        let bundleID = query.range(of: #"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"#, options: .regularExpression) != nil ? query : nil
        let parameter = id != nil ? "id" : bundleID != nil ? "bundleId" : "term"
        let endpoint = parameter == "term" ? "search" : "lookup"
        var url = URLComponents(string: "https://itunes.apple.com/" + endpoint)!
        url.queryItems = [URLQueryItem(name: parameter, value: id ?? bundleID ?? query), URLQueryItem(name: "country", value: country)]
        if endpoint == "search" {
            url.queryItems! += [URLQueryItem(name: "entity", value: "software"), URLQueryItem(name: "limit", value: "20")]
        }
        struct Response: Decodable { let results: [CatalogApp] }
        let result = try JSONDecoder().decode(Response.self, from: await request(url.url!, timeout: timeout))
        var seen = Set<Int64>()
        return result.results.filter {
            $0.id > 0 && (id == nil || String($0.id) == id) &&
                (bundleID == nil || $0.bundleID.lowercased() == bundleID?.lowercased()) && seen.insert($0.id).inserted
        }
    }
    static func history(_ appID: String, source: VersionSource) async throws -> [CatalogHistoryVersion] {
        guard DownloadCatalog.numericID(appID) else { throw DeskError("请输入有效的 App ID。") }
        let address: String
        switch source {
        case .timbrd: address = "https://api.timbrd.com/apple/app-version/index.php?id=\(appID)"
        case .iosdump: address = "https://iosdump.apdoilaan.work/history/\(appID)"
        case .bilin: address = "https://apis.bilin.eu.org/history/\(appID)"
        }
        return try parseHistory(await request(URL(string: address)!))
    }
    static func parseHistory(_ data: Data) throws -> [CatalogHistoryVersion] {
        let json = try JSONSerialization.jsonObject(with: data)
        let container = (json as? [String: Any])?["data"] ?? json
        guard let rows = container as? [[String: Any]] else { throw DeskError("版本来源返回的格式无法识别。") }
        func text(_ row: [String: Any], _ keys: [String]) -> String {
            for key in keys {
                if let value = row[key] as? String, !value.isEmpty { return value.trimmingCharacters(in: .whitespacesAndNewlines) }
                if let value = row[key] as? NSNumber { return value.stringValue }
            }
            return ""
        }
        var seen = Set<String>()
        return rows.compactMap { row in
            let id = text(row, ["external_identifier", "versionId", "version_id", "id"])
            guard DownloadCatalog.numericID(id), seen.insert(id).inserted else { return nil }
            let version = text(row, ["bundle_version", "version", "bundleShortVersionString"])
            return CatalogHistoryVersion(id: id, version: version.isEmpty ? "未知版本" : String(version.prefix(64)), date: text(row, ["created_at", "createTime", "updateTime", "date", "time"]))
        }.sorted { $0.id.compare($1.id, options: .numeric) == .orderedDescending }
    }
}
