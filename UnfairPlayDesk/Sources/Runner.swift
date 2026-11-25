import Foundation
import Combine
import Darwin

enum InputPrompt: Hashable {
    case account, password, verification, verificationChoice, passphrase

    static func match(_ line: String) -> Self? {
        let text = line.trimmingCharacters(in: .whitespaces).lowercased()
        if text.hasSuffix("enter apple id (email address or phone number):") { return .account }
        if text.hasSuffix("password:") { return .password }
        if text.hasSuffix("enter 2fa code:") { return .verification }
        if text.hasSuffix("if you received a code, enter it or leave blank:") { return .verificationChoice }
        if text.contains("enter passphrase to unlock") && text.hasSuffix(":") { return .passphrase }
        return nil
    }

    var title: String {
        switch self {
        case .account: "Apple ID"
        case .password: "Apple 账户密码"
        case .verification: "双重认证验证码"
        case .verificationChoice: "登录未确认"
        case .passphrase: "凭据库解锁口令"
        }
    }
}

final class Runner: ObservableObject {
    private struct BatchFailureSnapshot {
        var diagnostic: TaskDiagnostic
        var output: String
        var log: String
        var secrets: [String]
    }

    static var active: [UUID: Runner] = [:]
    let id = UUID()
    @Published var busy = false
    @Published var log = "操作结果会显示在这里。"
    @Published var title = "就绪"
    @Published private(set) var inputPrompt: InputPrompt?
    var canReply: Bool { inputPrompt != nil }
    @Published var hint: String?
    @Published var progress: Double?
    @Published var currentLine = ""
    var output = ""
    private var diagnostic: TaskDiagnostic?
    private var diagnosticSecrets: [String] = []
    private var diagnosticPhase = ""
    private var batchFailure: BatchFailureSnapshot?
    var process: Process?
    private var sessionKeyChannel: SessionKeyChannel?
    var master: Int32 = -1
    var outputHandle: FileHandle?
    var finished: ((Bool) -> Void)?
    var cancelled = false
    var privileged = false
    var saving = false
    private var holdsCompletion = false
    private var batchID: UUID?
    var background = false
    var pendingBytes = Data()
    private var pendingCR = false
    private var submittedPromptLine: String?
    private var generation = UUID()
    private var progressBuffer = ""
    private let verify: () async throws -> Void
    init(verify: @escaping () async throws -> Void = { try await Core.bundleVerification.value }) { self.verify = verify }
    var worker: URL {
        #if DESK_TESTING
        return URL(fileURLWithPath: ProcessInfo.processInfo.environment["DESK_WORKER"]!)
        #else
        return Bundle.main.resourceURL!.appendingPathComponent("Tools/worker")
        #endif
    }
    func launch(
        _ url: URL,
        _ args: [String],
        title: String,
        privileged: Bool = false,
        holdsCompletion: Bool = false,
        sessionAccount: UUID? = nil,
        deletingSession: Bool = false,
        batchID: UUID? = nil,
        done: ((Bool) -> Void)? = nil
    ) {
        if let batchID {
            guard self.batchID == batchID, !saving, process == nil, !cancelled else { done?(false); return }
        } else {
            guard !busy else { return }
            batchFailure = nil
        }
        generation = UUID()
        diagnostic = TaskDiagnostic(title: title, tool: url.lastPathComponent)
        diagnosticSecrets = []
        diagnosticPhase = ""
        diagnostic?.stage("校验应用组件")
        let token = generation
        self.title = title; hint = nil; log = ""; output = ""; currentLine = ""; progress = nil; progressBuffer = ""; pendingBytes = Data(); pendingCR = false; submittedPromptLine = nil
        finished = done; self.privileged = privileged; self.holdsCompletion = holdsCompletion && done != nil; cancelled = false
        busy = true; inputPrompt = nil; Runner.active[id] = self
        Task { @MainActor in
            do { try await verify() }
            catch { failLaunch(error.localizedDescription, itemTitle: title); return }
            if cancelled {
                updateCompletionState()
                self.title = "操作已取消"
                diagnostic?.finish("已取消")
                let callback = finished; finished = nil; callback?(false); return
            }
            startProcess(url, args, itemTitle: title, token: token, sessionAccount: sessionAccount, deletingSession: deletingSession)
        }
    }
    private func startProcess(_ url: URL, _ args: [String], itemTitle: String, token: UUID, sessionAccount: UUID?, deletingSession: Bool) {
        diagnostic?.stage("启动任务")
        let task = Process(); task.executableURL = worker
        let channel: SessionKeyChannel?
        do { channel = try sessionAccount.map { _ in try SessionKeyChannel() } }
        catch { failLaunch(error.localizedDescription, itemTitle: itemTitle); return }
        let channelOption = channel == nil ? [] : ["--session-channel"]
        let toolOptions = channel == nil ? [] : ["--desk-session-fd", "3"]
        task.arguments = ["--parent", String(getpid())] + channelOption + [url.path] + toolOptions + args
        var environment = ProcessInfo.processInfo.environment
        environment["TERM"] = "dumb"; environment["NO_COLOR"] = "1"
        task.environment = environment
        var primary: Int32 = -1, secondary: Int32 = -1
        guard openpty(&primary, &secondary, nil, nil, nil) == 0 else { failLaunch("无法创建交互终端。", itemTitle: itemTitle); return }
        var attr = termios()
        guard tcgetattr(secondary, &attr) == 0 else { close(primary); close(secondary); failLaunch("无法配置交互终端。", itemTitle: itemTitle); return }
        attr.c_lflag &= ~tcflag_t(ECHO | ECHONL)
        guard tcsetattr(secondary, TCSANOW, &attr) == 0 else { close(primary); close(secondary); failLaunch("无法关闭输入回显。", itemTitle: itemTitle); return }
        let flags = fcntl(primary, F_GETFL)
        guard flags >= 0, fcntl(primary, F_SETFL, flags | O_NONBLOCK) == 0 else { close(primary); close(secondary); failLaunch("无法配置非阻塞终端。", itemTitle: itemTitle); return }
        let slave = FileHandle(fileDescriptor: secondary, closeOnDealloc: true)
        let reader = FileHandle(fileDescriptor: primary, closeOnDealloc: true)
        master = primary; outputHandle = reader
        task.standardInput = channel?.child ?? slave; task.standardOutput = slave; task.standardError = slave
        reader.readabilityHandler = { [weak self] handle in
            var bytes = [UInt8](repeating: 0, count: 8192)
            let count = read(primary, &bytes, bytes.count)
            if count > 0 {
                let data = Data(bytes.prefix(count))
                DispatchQueue.main.async { if self?.generation == token { self?.receive(data) } }
            } else if count == 0 || errno == EIO { handle.readabilityHandler = nil }
        }
        task.terminationHandler = { [weak self] process in
            channel?.cancel()
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
                let ok = process.terminationStatus == 0 && !self.cancelled
                self.diagnostic?.finish(self.cancelled ? "已取消" : ok ? "成功" : "失败",
                                        exitStatus: process.terminationStatus, signalled: process.terminationReason == .uncaughtSignal)
                self.updateCompletionState()
                self.inputPrompt = nil; self.master = -1
                self.outputHandle = nil; self.process = nil; self.sessionKeyChannel = nil
                self.title = self.cancelled ? "操作已取消" : ok ? "操作完成" : "操作失败"
                self.hint = ok || self.cancelled ? nil : Core.errorHint(self.output)
                if ok { self.progress = 1 }
                else if !self.cancelled { self.captureBatchFailure(itemTitle: itemTitle) }
                let callback = self.finished; self.finished = nil
                callback?(ok)
            }
        }
        do {
            try task.run(); try? slave.close()
            sessionKeyChannel = channel
            if let channel, let sessionAccount {
                channel.serve(account: sessionAccount, deleting: deletingSession)
            }
            process = task; busy = true; inputPrompt = nil; Runner.active[id] = self
        } catch {
            reader.readabilityHandler = nil; try? slave.close(); try? reader.close()
            outputHandle = nil; master = -1; failLaunch(error.localizedDescription, itemTitle: itemTitle)
        }
    }
    func failLaunch(_ reason: String, itemTitle: String? = nil) {
        diagnostic?.finish("启动失败")
        log = reason; output = reason; title = "启动失败"; hint = reason; inputPrompt = nil
        captureBatchFailure(itemTitle: itemTitle ?? title, detail: reason)
        updateCompletionState()
        let callback = finished; finished = nil; callback?(false)
    }
    private func updateCompletionState() {
        saving = holdsCompletion
        busy = holdsCompletion || batchID != nil
        if !busy { Runner.active.removeValue(forKey: id) }
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
            if let start = line.firstIndex(of: "{"),
               let data = String(line[start...]).trimmingCharacters(in: .whitespacesAndNewlines).data(using: .utf8),
               let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
               let message = json["message"] as? String,
               json["phase"] != nil || message.hasPrefix("正在") || message.hasPrefix("首次准备：") || message.hasPrefix("已提取认证组件") || message == "已复用认证组件缓存" || message == "认证组件准备完成，正在验证 Apple 账户" {
                title = message
                if let phase = json["phase"] as? String {
                    if phase == "stage" || phase != diagnosticPhase { diagnostic?.stage(message) }
                    diagnosticPhase = phase
                } else { diagnostic?.stage(message) }
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
        // Drop stale terminal percentages, while retaining a split JSON record.
        if let start = progressBuffer.firstIndex(of: "{") { progressBuffer = String(progressBuffer[start...]) }
        else if progressBuffer.utf8.count > 8192 { progressBuffer = String(progressBuffer.suffix(4096)) }
        output += clean
        if output.count > 200000 { output = Self.trimmedSuffix(output, limit: 150000) }
        var history = log, line = currentLine
        for c in clean.replacingOccurrences(of: "\r\n", with: "\n") {
            if c == "\r" { pendingCR = true }
            else if c == "\n" { history += line + "\n"; line = ""; pendingCR = false }
            else {
                if pendingCR { line = ""; pendingCR = false }
                line.append(c)
            }
        }
        log = history.count > 40000 ? Self.trimmedSuffix(history, limit: 30000) : history
        currentLine = line.count > 8000 ? String(line.suffix(8000)) : line
        let prompt = InputPrompt.match(currentLine)
        if currentLine != submittedPromptLine || clean.contains("\n") || clean.contains("\r") { submittedPromptLine = nil }
        let next = busy && !privileged && !cancelled && master >= 0 && submittedPromptLine == nil ? prompt : nil
        if inputPrompt != next { inputPrompt = next }
        if let prompt, submittedPromptLine == nil {
            title = prompt == .verificationChoice ? "等待确认登录" : "等待输入" + prompt.title
        }
        if !structuredProgress, let range = clean.range(of: #"([0-9]{1,3})%"#, options: [.regularExpression, .backwards]), let number = Double(clean[range].dropLast()) { progress = min(number / 100, 1) }
    }
    func reply(_ value: String) {
        guard canReply, master >= 0 else { return }
        let prompt = inputPrompt
        if prompt != .account, !value.isEmpty { diagnosticSecrets.append(value) }
        let data = Data((value + "\n").utf8)
        let written = data.withUnsafeBytes { write(master, $0.baseAddress, $0.count) }
        guard written == data.count else { stop(); return }
        submittedPromptLine = currentLine
        inputPrompt = nil
        switch prompt {
        case .verification, .verificationChoice: recordStage("正在提交 Apple 验证信息")
        case .password: recordStage("正在验证 Apple 账户")
        case .account: recordStage("正在提交 Apple ID")
        case .passphrase: recordStage("正在解锁凭据库")
        case nil: break
        }
    }
    @MainActor func fileWork<T>(_ title: String, preserveFailure: Bool = false, operation: @escaping () throws -> T) async -> Result<T, Error> {
        let hadPriorFailure = busy && diagnostic?.hasFailedResult == true
        let previousTitle = self.title
        let previousHint = self.hint
        if !busy {
            batchFailure = nil
            diagnostic = TaskDiagnostic(title: title, tool: "文件操作")
            diagnosticSecrets = []
            output = ""; log = ""
        }
        diagnostic?.stage(title)
        busy = true; saving = true; inputPrompt = nil; self.title = title; progress = nil
        if !(preserveFailure && hadPriorFailure) { hint = nil }
        Runner.active[id] = self
        let result = await Task.detached(priority: .userInitiated) { Result { try operation() } }.value
        updateCompletionState()
        switch result {
        case .success:
            if preserveFailure && hadPriorFailure {
                self.title = previousTitle
                self.hint = previousHint
            } else {
                self.title = "操作完成"
                diagnostic?.finish("成功")
            }
        case .failure(let error):
            self.title = "操作失败"
            if output.isEmpty { output = error.localizedDescription }
            if log.isEmpty { log = error.localizedDescription + "\n" }
            diagnostic?.finish("失败")
        }
        return result
    }
    @MainActor func beginBatch(_ title: String, tool: String = "unfairplay") -> UUID? {
        guard !busy else { return nil }
        let token = UUID()
        batchID = token
        self.title = title
        var initial = TaskDiagnostic(title: title, tool: tool)
        initial.stage("准备任务")
        diagnostic = initial
        batchFailure = nil
        diagnosticSecrets = []
        diagnosticPhase = ""
        output = ""; log = ""; currentLine = ""
        cancelled = false; privileged = false; saving = false; inputPrompt = nil; progress = nil; hint = nil
        busy = true
        Runner.active[id] = self
        return token
    }
    @MainActor func recordBatchFailure(_ stepTitle: String, detail: String) {
        if batchID != nil {
            if diagnostic == nil {
                diagnostic = TaskDiagnostic(title: stepTitle, tool: "unfairplay")
            }
            diagnostic?.stage(stepTitle)
            diagnostic?.finish("失败")
            title = "操作失败"
            hint = detail
            output = output.isEmpty ? detail : Self.trimmedSuffix(output + "\n" + detail, limit: 150000)
            log = log.isEmpty ? detail + "\n" : Self.trimmedSuffix(log + (log.hasSuffix("\n") ? "" : "\n") + detail + "\n", limit: 30000)
            captureBatchFailure(itemTitle: stepTitle, detail: detail)
        } else {
            if diagnostic == nil {
                diagnostic = TaskDiagnostic(title: stepTitle, tool: "UnfairPlay")
            }
            diagnostic?.stage(stepTitle)
            diagnostic?.finish("失败")
            if output.isEmpty { output = detail }
            if log.isEmpty { log = detail + "\n" }
        }
    }
    @MainActor func markDiagnosticFailure(_ stageName: String? = nil, detail: String? = nil) {
        if let stageName, !stageName.isEmpty { diagnostic?.stage(stageName) }
        diagnostic?.finish("失败")
        if let detail, !detail.isEmpty, output.isEmpty { output = detail }
    }
    @MainActor func finishBatch(_ token: UUID) {
        guard batchID == token, process == nil else { return }
        if cancelled {
            if diagnostic?.result != "已取消" { diagnostic?.finish("已取消") }
        } else if let failure = batchFailure {
            diagnostic = failure.diagnostic
            output = failure.output
            log = failure.log
            for secret in failure.secrets where !diagnosticSecrets.contains(secret) {
                diagnosticSecrets.append(secret)
            }
            title = "操作失败"
        } else if diagnostic?.hasFailedResult != true {
            diagnostic?.finish("成功")
        }
        batchFailure = nil
        batchID = nil
        holdsCompletion = false
        updateCompletionState()
    }
    @MainActor func finishCompletion() {
        guard holdsCompletion else { return }
        holdsCompletion = false
        updateCompletionState()
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
    func recordStage(_ title: String) {
        self.title = title
        progress = nil
        diagnostic?.stage(title)
    }
    func diagnosticReport(detail: String) -> String {
        if let failure = batchFailure, diagnostic?.hasFailedResult != true {
            var mergedSecrets = failure.secrets
            for secret in diagnosticSecrets where !mergedSecrets.contains(secret) {
                mergedSecrets.append(secret)
            }
            return failure.diagnostic.report(
                detail: detail,
                output: failure.output.isEmpty ? failure.log : failure.output,
                secrets: mergedSecrets
            )
        }
        var record = diagnostic ?? TaskDiagnostic(title: "应用操作", tool: "UnfairPlay")
        if diagnostic == nil { record.finish("应用提示") }
        return record.report(detail: detail, output: output.isEmpty ? log : output, secrets: diagnosticSecrets)
    }
    func stop() {
        guard !privileged && !saving else { return }
        cancelled = true; inputPrompt = nil; process?.terminate()
        sessionKeyChannel?.cancel()
    }

    private func captureBatchFailure(itemTitle: String, detail: String? = nil) {
        guard batchID != nil else { return }
        var failedDiag = diagnostic ?? TaskDiagnostic(title: itemTitle, tool: "unfairplay")
        if !failedDiag.hasFailedResult {
            failedDiag.finish("失败")
        }
        let rawOut = output.isEmpty ? (detail ?? "") : output
        let rawLog = log.isEmpty ? (rawOut.isEmpty ? "" : rawOut + "\n") : log
        let labeledOut = rawOut.isEmpty ? "[\(itemTitle)]" : "[\(itemTitle)]\n\(rawOut)"
        let labeledLog = rawLog.isEmpty ? "[\(itemTitle)]\n" : "[\(itemTitle)]\n\(rawLog)"

        if var existing = batchFailure {
            existing.diagnostic.stage("后续失败：\(itemTitle)")
            existing.output = Self.trimmedSuffix(existing.output + "\n" + labeledOut, limit: 150000)
            existing.log = Self.trimmedSuffix(existing.log + "\n" + labeledLog, limit: 30000)
            for secret in diagnosticSecrets where !existing.secrets.contains(secret) {
                existing.secrets.append(secret)
            }
            batchFailure = existing
        } else {
            batchFailure = BatchFailureSnapshot(
                diagnostic: failedDiag,
                output: rawOut,
                log: rawLog,
                secrets: diagnosticSecrets
            )
        }
    }

    private static func trimmedSuffix(_ text: String, limit: Int) -> String {
        guard text.count > limit else { return text }
        let tail = text.suffix(limit)
        if let newline = tail.firstIndex(of: "\n"), tail.index(after: newline) < tail.endIndex {
            return String(tail[tail.index(after: newline)...])
        }
        return String(tail)
    }
}
