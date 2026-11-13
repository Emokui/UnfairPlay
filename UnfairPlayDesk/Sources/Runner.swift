import Foundation
import Combine
import Darwin

final class Runner: ObservableObject {
    static var active: [UUID: Runner] = [:]
    let id = UUID()
    @Published var busy = false
    @Published var log = "操作结果会显示在这里。"
    @Published var title = "就绪"
    @Published var sensitive = true
    @Published var canReply = false
    @Published var hint: String?
    @Published var progress: Double?
    @Published var currentLine = ""
    var output = ""
    var process: Process?
    var master: Int32 = -1
    var outputHandle: FileHandle?
    var finished: ((Bool) -> Void)?
    var cancelled = false
    var privileged = false
    var saving = false
    var background = false
    var pendingBytes = Data()
    private var pendingCR = false
    private var generation = UUID()
    private var progressBuffer = ""
    private let verify: () async throws -> Void
    init(verify: @escaping () async throws -> Void = { try await Core.bundleVerification.value }) { self.verify = verify }
    var displayOutput: String {
        (log + currentLine)
            .replacingOccurrences(of: "preparing authentication; the first login may take a few minutes", with: "正在准备认证；首次需要下载组件，完成后自动复用缓存")
            .replacingOccurrences(of: "enter password:", with: "请输入 Apple 账户密码：")
            .replacingOccurrences(of: "enter 2FA code:", with: "请输入双重认证验证码：")
            .replacingOccurrences(of: "enter Apple ID (email address or phone number):", with: "请输入 Apple ID（邮箱或手机号）：")
            .replacingOccurrences(of: "enter passphrase to unlock", with: "请输入凭据库解锁口令：")
            .replacingOccurrences(of: "(this is separate from your Apple ID password)", with: "（与 Apple ID 密码不同）")
    }
    var worker: URL {
        #if DESK_TESTING
        return URL(fileURLWithPath: ProcessInfo.processInfo.environment["DESK_WORKER"]!)
        #else
        return Bundle.main.resourceURL!.appendingPathComponent("Tools/worker")
        #endif
    }
    func launch(_ url: URL, _ args: [String], title: String, privileged: Bool = false, done: ((Bool)->Void)? = nil) {
        guard !busy else { return }
        generation = UUID()
        let token = generation
        self.title = title; hint = nil; log = ""; output = ""; currentLine = ""; progress = nil; progressBuffer = ""; pendingBytes = Data(); pendingCR = false; sensitive = true
        finished = done; self.privileged = privileged; cancelled = false
        busy = true; canReply = false; Runner.active[id] = self
        Task { @MainActor in
            do { try await verify() }
            catch { failLaunch(error.localizedDescription); return }
            if cancelled {
                busy = false; Runner.active.removeValue(forKey: id); self.title = "操作已取消"
                let callback = finished; finished = nil; callback?(false); return
            }
            startProcess(url, args, token: token)
        }
    }
    private func startProcess(_ url: URL, _ args: [String], token: UUID) {
        let task = Process(); task.executableURL = worker
        task.arguments = ["--parent", String(getpid()), url.path] + args
        var environment = ProcessInfo.processInfo.environment
        environment["TERM"] = "dumb"; environment["NO_COLOR"] = "1"
        task.environment = environment
        var primary: Int32 = -1, secondary: Int32 = -1
        guard openpty(&primary, &secondary, nil, nil, nil) == 0 else { failLaunch("无法创建交互终端。"); return }
        var attr = termios()
        guard tcgetattr(secondary, &attr) == 0 else { close(primary); close(secondary); failLaunch("无法配置交互终端。"); return }
        attr.c_lflag &= ~tcflag_t(ECHO | ECHONL)
        guard tcsetattr(secondary, TCSANOW, &attr) == 0 else { close(primary); close(secondary); failLaunch("无法关闭输入回显。"); return }
        let flags = fcntl(primary, F_GETFL)
        guard flags >= 0, fcntl(primary, F_SETFL, flags | O_NONBLOCK) == 0 else { close(primary); close(secondary); failLaunch("无法配置非阻塞终端。"); return }
        let slave = FileHandle(fileDescriptor: secondary, closeOnDealloc: true)
        let reader = FileHandle(fileDescriptor: primary, closeOnDealloc: true)
        master = primary; outputHandle = reader
        task.standardInput = slave; task.standardOutput = slave; task.standardError = slave
        reader.readabilityHandler = { [weak self] handle in
            var bytes = [UInt8](repeating: 0, count: 8192)
            let count = read(primary, &bytes, bytes.count)
            if count > 0 {
                let data = Data(bytes.prefix(count))
                DispatchQueue.main.async { if self?.generation == token { self?.receive(data) } }
            } else if count == 0 || errno == EIO { handle.readabilityHandler = nil }
        }
        task.terminationHandler = { [weak self] process in
            reader.readabilityHandler = nil
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                guard let self else { return }
                _ = fcntl(primary, F_SETFL, O_NONBLOCK)
                var bytes = [UInt8](repeating: 0, count: 8192)
                while true {
                    let count = read(primary, &bytes, bytes.count)
                    if count <= 0 { break }
                    self.receive(Data(bytes.prefix(count)))
                }
                if !self.pendingBytes.isEmpty { self.append(String(decoding: self.pendingBytes, as: UTF8.self)); self.pendingBytes = Data() }
                self.busy = false; self.canReply = false; self.master = -1
                self.outputHandle = nil; self.process = nil
                Runner.active.removeValue(forKey: self.id)
                let ok = process.terminationStatus == 0 && !self.cancelled
                self.title = self.cancelled ? "操作已取消" : ok ? "操作完成" : "操作失败"
                self.hint = ok || self.cancelled ? nil : Core.errorHint(self.output)
                if ok { self.progress = 1 }
                let callback = self.finished; self.finished = nil
                callback?(ok)
            }
        }
        do {
            try task.run(); try? slave.close()
            process = task; busy = true; canReply = !privileged; Runner.active[id] = self
        } catch {
            reader.readabilityHandler = nil; try? slave.close(); try? reader.close()
            outputHandle = nil; master = -1; failLaunch(error.localizedDescription)
        }
    }
    func failLaunch(_ reason: String) {
        log = reason; title = "启动失败"; hint = reason; busy = false; canReply = false
        Runner.active.removeValue(forKey: id)
        let callback = finished; finished = nil; callback?(false)
    }
    func receive(_ data: Data) {
        pendingBytes.append(data)
        // Keep an incomplete UTF-8 suffix for the next read, rather than corrupting Chinese text.
        for retained in 0...min(3, pendingBytes.count) {
            let end = pendingBytes.count - retained
            if let text = String(data: pendingBytes.prefix(end), encoding: .utf8) {
                pendingBytes = Data(pendingBytes.suffix(retained)); append(text); return
            }
        }
        append(String(decoding: pendingBytes, as: UTF8.self)); pendingBytes = Data()
    }
    func append(_ chunk: String) {
        let clean = chunk.replacingOccurrences(of: "\u{1B}\\[[0-9;]*[a-zA-Z]", with: "", options: .regularExpression)
        var structuredProgress = false
        progressBuffer += clean
        while let end = progressBuffer.firstIndex(of: "\n") {
            let line = String(progressBuffer[..<end])
            progressBuffer.removeSubrange(...end)
            if let data = line.trimmingCharacters(in: .whitespacesAndNewlines).data(using: .utf8),
               let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
               let message = json["message"] as? String,
               message.hasPrefix("正在") || message.hasPrefix("首次准备：") || message.hasPrefix("已提取认证组件") || message == "已复用认证组件缓存" || message == "认证组件准备完成，正在验证 Apple 账户" {
                title = message
                if let phase = json["phase"] as? String {
                    structuredProgress = true
                    if let done = json["completed"] as? Double, let total = json["total"] as? Double, total > 0 {
                        progress = min(1, max(0, done / total))
                        title += " (\(Int(done))/\(Int(total)))"
                    } else { progress = nil }
                    if phase == "stage" { progress = nil }
                }
            }
        }
        if progressBuffer.utf8.count > 8192 { progressBuffer = "" }
        output += clean
        if output.count > 200000 { output = String(output.suffix(150000)) }
        var history = log, line = currentLine
        for c in clean.replacingOccurrences(of: "\r\n", with: "\n") {
            if c == "\r" { pendingCR = true }
            else if c == "\n" { history += line + "\n"; line = ""; pendingCR = false }
            else {
                if pendingCR { line = ""; pendingCR = false }
                line.append(c)
            }
        }
        log = history.count > 40000 ? String(history.suffix(30000)) : history
        currentLine = line.count > 8000 ? String(line.suffix(8000)) : line
        if currentLine.contains("enter password:") { title = "等待输入 Apple 账户密码" }
        else if currentLine.contains("enter 2FA code:") { title = "等待输入双重认证验证码" }
        else if currentLine.contains("enter passphrase to unlock") { title = "等待输入凭据库口令" }
        if !structuredProgress, let range = clean.range(of: #"([0-9]{1,3})%"#, options: [.regularExpression, .backwards]), let number = Double(clean[range].dropLast()) { progress = min(number / 100, 1) }
    }
    func reply(_ value: String) {
        guard busy, master >= 0 else { return }
        let data = Data((value + "\n").utf8)
        data.withUnsafeBytes { _ = write(master, $0.baseAddress, $0.count) }
    }
    @MainActor func fileWork<T>(_ title: String, operation: @escaping () throws -> T) async -> Result<T, Error> {
        busy = true; saving = true; canReply = false; self.title = title; progress = nil; hint = nil
        Runner.active[id] = self
        let result = await Task.detached(priority: .userInitiated) { Result { try operation() } }.value
        saving = false; busy = false
        Runner.active.removeValue(forKey: id)
        switch result {
        case .success: self.title = "操作完成"
        case .failure: self.title = "操作失败"
        }
        return result
    }
    @MainActor func saveFile(_ operation: @escaping () throws -> Void) async -> Result<Void, Error> {
        let started = Date()
        let result = await fileWork("正在保存文件…", operation: operation)
        log += String(format: "\n文件保存耗时：%.2f 秒\n", Date().timeIntervalSince(started))
        switch result {
        case .success: title = "文件已保存"
        case .failure: title = "文件尚未保存"
        }
        return result
    }
    func stop() {
        guard !privileged && !saving else { return }
        cancelled = true; process?.terminate()
    }
}
