import Foundation

struct TaskDiagnostic {
    private struct Stage {
        let name: String
        let time: TimeInterval
    }

    private let started = Date()
    private let uptime = ProcessInfo.processInfo.systemUptime
    private let title: String
    private let tool: String
    private var stages: [Stage] = []
    private var elapsed: TimeInterval?
    private var result = "运行中"
    private var exitStatus: Int32?
    private var signalled = false

    init(title: String, tool: String) {
        self.title = title
        self.tool = tool
    }

    mutating func stage(_ name: String) {
        guard stages.last?.name != name else { return }
        elapsed = nil
        stages.append(Stage(name: name, time: ProcessInfo.processInfo.systemUptime - uptime))
        if stages.count > 128 { stages.removeFirst() }
    }

    mutating func finish(_ result: String, exitStatus: Int32? = nil, signalled: Bool = false) {
        self.result = result
        elapsed = ProcessInfo.processInfo.systemUptime - uptime
        if let exitStatus {
            self.exitStatus = exitStatus
            self.signalled = signalled
        }
    }

    func report(detail: String, output: String, secrets: [String]) -> String {
        let duration = elapsed ?? (ProcessInfo.processInfo.systemUptime - uptime)
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "开发构建"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "—"
        var lines = [
            "UnfairPlay 诊断报告", "版本  \(version) (\(build))",
            "系统  \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "开始  \(ISO8601DateFormatter().string(from: started))",
            "任务  \(title)", "工具  \(tool)", "结果  \(result)",
            String(format: "总耗时  %.2f 秒", duration)
        ]
        if let exitStatus { lines.append("\(signalled ? "终止信号" : "退出码")  \(exitStatus)") }
        lines += ["", "阶段耗时"]
        for (index, stage) in stages.enumerated() {
            let end = index + 1 < stages.count ? stages[index + 1].time : duration
            lines.append(String(format: "+%.2f 秒  %@  (%.2f 秒)", stage.time, stage.name, max(0, end - stage.time)))
        }
        lines += ["", "错误摘要", detail, "", "最近输出（最多 24,000 字符）"]
        let allowedFields: Set<String> = ["time", "level", "phase", "message", "error", "success", "elapsed_ms", "previous_stage_ms", "completed", "total"]
        for line in output.suffix(24_000).components(separatedBy: .newlines) {
            if let start = line.firstIndex(of: "{"),
               let json = try? JSONSerialization.jsonObject(with: Data(line[start...].utf8)) as? [String: Any] {
                let filtered = json.filter { allowedFields.contains($0.key) }
                if !filtered.isEmpty,
                   let bytes = try? JSONSerialization.data(withJSONObject: filtered, options: [.sortedKeys]),
                   let text = String(data: bytes, encoding: .utf8) { lines.append(text) }
            } else {
                lines.append(line)
            }
        }
        return Self.redact(lines.joined(separator: "\n") + "\n", secrets: secrets)
    }

    private static func redact(_ text: String, secrets: [String]) -> String {
        var result = text
        for secret in secrets.sorted(by: { $0.count > $1.count }) where !secret.isEmpty {
            result = result.replacingOccurrences(of: secret, with: "[已隐藏]")
        }
        result = result.replacingOccurrences(of: NSHomeDirectory(), with: "~")
        let replacements = [
            (#"/Users/[^/\s\"<>]+"#, "/Users/[用户]"),
            (#"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"#, "[邮箱]"),
            (#"https?://[^\s\"<>]+"#, "[URL]"),
            (#"(?i)(password|passphrase|passwordtoken|token|authorization|cookie|verificationcode|dsid|appleid|apple_id)\"?\s*[=:]\s*(?:\"(?:\\.|[^\"\\])*\"|'[^']*'|[^\s,;]+)"#, "$1=[已隐藏]"),
            (#"(?<![0-9])\+?[0-9]{10,15}(?![0-9])"#, "[编号]")
        ]
        for (pattern, replacement) in replacements {
            result = result.replacingOccurrences(of: pattern, with: replacement, options: .regularExpression)
        }
        return result
    }
}
