import Foundation
import Combine
import Darwin

struct Profile: Codable, Identifiable, Hashable {
    var id: UUID
    var name: String
    var appleID: String?
    var requestedAppleID: String?
    var deletionPending: Bool?
}

final class Store: ObservableObject {
    @Published var profiles: [Profile] = []
    @Published var selected: UUID? {
        didSet { UserDefaults.standard.set(selected?.uuidString, forKey: "selectedAccountProfile"); refreshModel() }
    }
    @Published var error: String?
    @Published var storageReady = false
    @Published var modelReady = false
    @Published var modelMessage = "尚未选择账户"
    @Published var unresolvedReports = 0
    let root: URL
    let modelTool: URL?
    private var snapshot: Data?
    private var modelCache: [UUID: (stamp: [String: Core.FileStamp]?, result: (Bool, String))] = [:]
    private var checks: Set<UUID> = []
    private var diagnosticRunners: [UUID: Runner] = [:]
    private var versions: [UUID: Int] = [:]
    private var lockHandle: FileHandle?
    var profileURL: URL? { selected.map { root.appendingPathComponent("Models/\($0.uuidString)") } }
    var selectedProfile: Profile? { profiles.first { $0.id == selected } }
    var canUseSelected: Bool { storageReady && selectedProfile != nil && selectedProfile?.deletionPending != true }

    init(root: URL? = nil, modelTool: URL? = nil) {
        self.root = (root ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("UnfairPlayDesk")).resolvingSymlinksInPath()
        self.modelTool = modelTool ?? Bundle.main.resourceURL?.appendingPathComponent("Tools/modelcheck")
        do {
            try Core.privateDirectory(self.root)
            let lock = self.root.appendingPathComponent(".store.lock")
            let descriptor = open(lock.path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
            guard descriptor >= 0 else { throw DeskError("无法锁定账户数据目录。") }
            guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { close(descriptor); throw DeskError("已有另一个工作台正在使用这些账户，请先关闭另一个实例。") }
            lockHandle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            let registry = self.root.appendingPathComponent("profiles.json")
            if try Core.fileStamp(registry) != nil {
                snapshot = try Data(contentsOf: registry)
                profiles = try JSONDecoder().decode([Profile].self, from: snapshot!)
                guard Set(profiles.map(\.id)).count == profiles.count else { throw DeskError("账户配置包含重复标识，已锁定配置写入。") }
            }
            storageReady = true
            if let saved = UserDefaults.standard.string(forKey: "selectedAccountProfile"), let id = UUID(uuidString: saved), profiles.contains(where: { $0.id == id }) { selected = id }
            else { selected = profiles.first?.id }
            do {
                try WorkStage.recover(root: self.root)
                // Establish ownership of legacy reports while the models are still available.
                for profile in profiles { try Core.associateLegacyReports(profile.id, root: self.root) }
            } catch { self.error = "旧数据整理未完成，原文件已保留。相关清理操作会停止并报告问题：\n\(error.localizedDescription)" }
            refreshLegacyCount()
            refreshModel()
        } catch {
            storageReady = false
            self.error = "账户配置或数据目录无法安全读取，已禁止修改，避免覆盖旧资料。\n\(error.localizedDescription)"
        }
    }
    func save() throws {
        guard storageReady else { throw DeskError("账户配置处于只读保护状态，请先修复读取问题并重新打开软件。") }
        let path = root.appendingPathComponent("profiles.json")
        let disk = try Core.fileStamp(path) != nil ? try Data(contentsOf: path) : nil
        guard disk == snapshot else { throw DeskError("账户配置已在其他位置修改。请重新打开软件后再操作，旧配置未被覆盖。") }
        let data = try JSONEncoder().encode(profiles)
        let temp = root.appendingPathComponent(".profiles-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: temp) }
        try data.write(to: temp)
        try Core.commit(temp, to: path)
        snapshot = data
    }
    func profile(for email: String) -> Profile? {
        let key = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return profiles.first { ($0.appleID ?? $0.requestedAppleID)?.lowercased() == key }
    }
    func add(_ name: String, requestedAppleID: String? = nil) -> Profile? {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard storageReady, !name.isEmpty else { return nil }
        let profile = Profile(id: UUID(), name: name, requestedAppleID: requestedAppleID?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
        do {
            try Core.privateDirectory(root.appendingPathComponent("Models/\(profile.id.uuidString)"))
            profiles.append(profile)
            do { try save() } catch { profiles.removeAll { $0.id == profile.id }; throw error }
            selected = profile.id; return profile
        } catch { self.error = error.localizedDescription; return nil }
    }
    func bindIdentity(_ id: UUID, email: String) throws {
        guard let index = profiles.firstIndex(where: { $0.id == id }) else { throw DeskError("账户档案不存在。") }
        let canonical = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !canonical.isEmpty else { throw DeskError("未能读取真实 Apple 账户身份。") }
        if let expected = profiles[index].appleID {
            guard expected.lowercased() == canonical else { throw DeskError("登录账户与此档案绑定的 Apple ID 不一致，已阻止操作。请清除此账户登陆后使用 \(expected) 登录。") }
            return
        }
        guard !profiles.contains(where: { $0.id != id && $0.appleID?.lowercased() == canonical }) else { throw DeskError("这个 Apple ID 已绑定其他档案，请切换到原档案使用。") }
        let previous = profiles[index]
        profiles[index].appleID = canonical
        profiles[index].requestedAppleID = nil
        do { try save() } catch { profiles[index] = previous; throw error }
    }
    func markDeleting(_ id: UUID) throws {
        guard let index = profiles.firstIndex(where: { $0.id == id }) else { return }
        let previous = profiles[index]
        profiles[index].deletionPending = true
        do { try save() } catch { profiles[index] = previous; throw error }
        diagnosticRunners[id]?.stop()
        refreshModel(force: true)
    }
    func remove(_ account: Profile) throws {
        let previous = profiles
        profiles.removeAll { $0.id == account.id }
        do { try save() } catch { profiles = previous; throw error }
        modelCache.removeValue(forKey: account.id)
        if selected == account.id { selected = profiles.first?.id }
        refreshLegacyCount()
    }
    func refreshLegacyCount() {
        unresolvedReports = ((try? FileManager.default.contentsOfDirectory(at: root.appendingPathComponent("Reports"), includingPropertiesForKeys: nil)) ?? []).filter { $0.pathExtension == "json" }.count
    }
    func copyValidatedModels(_ source: URL, to dest: URL) throws {
        guard canUseSelected else { throw DeskError("当前档案不可修改。") }
        try Core.installModels(source, to: dest)
        refreshModel(force: true)
    }
    func refreshModel(force: Bool = false) {
        guard let id = selected, canUseSelected, let directory = profileURL else {
            modelReady = false; modelMessage = selectedProfile?.deletionPending == true ? "删除尚未完成，请继续删除此档案" : "尚未选择可用账户"; return
        }
        if force { modelCache.removeValue(forKey: id); versions[id, default: 0] += 1 }
        let stamp = try? Core.modelStamp(directory)
        if let cached = modelCache[id], cached.stamp == stamp { modelReady = cached.result.0; modelMessage = cached.result.1; return }
        modelReady = false; modelMessage = "正在校验模型…"
        guard !checks.contains(id) else { return }
        checks.insert(id)
        let version = versions[id, default: 0]
        DispatchQueue.global(qos: .utility).async {
            do { _ = try Core.modelFiles(directory) }
            catch {
                DispatchQueue.main.async { self.finishCheck(id, version: version, stamp: stamp, result: (false, error.localizedDescription)) }
                return
            }
            DispatchQueue.main.async {
                guard let tool = self.modelTool else { self.finishCheck(id, version: version, stamp: stamp, result: (false, "缺少模型校验工具")); return }
                let runner = Runner()
                runner.background = true
                self.diagnosticRunners[id] = runner
                runner.launch(tool, ["--model", directory.path], title: "校验模型") { ok in
                    let data = runner.output.data(using: .utf8) ?? Data()
                    let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                    let valid = ok && (json?["checks"] as? [String: Any])?["model_valid"] as? Bool == true
                    self.finishCheck(id, version: version, stamp: stamp, result: (valid, valid ? "模型已校验，可用于解密" : "模型校验失败，请检查格式、权限或重新初始化"))
                }
            }
        }
    }
    private func finishCheck(_ id: UUID, version: Int, stamp: [String: Core.FileStamp]?, result: (Bool, String)) {
        checks.remove(id)
        diagnosticRunners.removeValue(forKey: id)
        guard versions[id, default: 0] == version else { if selected == id { refreshModel() }; return }
        let directory = root.appendingPathComponent("Models/\(id.uuidString)")
        guard (try? Core.modelStamp(directory)) == stamp else { if selected == id { refreshModel() }; return }
        modelCache[id] = (stamp, result)
        if selected == id {
            modelReady = canUseSelected && result.0
            modelMessage = canUseSelected ? result.1 : "删除尚未完成，请继续删除此档案"
        }
    }
}
