import Foundation

struct TaskDiagnostic {
    private struct Stage {
        let name: String
        let time: TimeInterval
    }

    private static let allowedFields: Set<String> = [
        "time", "level", "phase", "message", "error", "success",
        "elapsed_ms", "previous_stage_ms", "completed", "total"
    ]
    private static let recentOutputLimit = 24_000

    private let started = Date()
    private let uptime = ProcessInfo.processInfo.systemUptime
    private let title: String
    private let tool: String
    private var stages: [Stage] = []
    private var elapsed: TimeInterval?
    private(set) var result = "运行中"
    private var exitStatus: Int32?
    private var signalled = false

    var hasFailedResult: Bool {
        result == "失败" || result == "已取消" || result == "启动失败"
    }

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
        var headerLines = [
            "UnfairPlay 诊断报告", "版本  \(version) (\(build))",
            "系统  \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "开始  \(ISO8601DateFormatter().string(from: started))",
            "任务  \(title)", "工具  \(tool)", "结果  \(result)",
            String(format: "总耗时  %.2f 秒", duration)
        ]
        if let exitStatus { headerLines.append("\(signalled ? "终止信号" : "退出码")  \(exitStatus)") }
        headerLines += ["", "阶段耗时"]
        for (index, stage) in stages.enumerated() {
            let end = index + 1 < stages.count ? stages[index + 1].time : duration
            headerLines.append(String(format: "+%.2f 秒  %@  (%.2f 秒)", stage.time, stage.name, max(0, end - stage.time)))
        }
        headerLines += ["", "错误摘要", detail, "", "最近输出（最多 24,000 字符）"]

        let sanitizedOutput = Self.sanitizeOutput(output).joined(separator: "\n")
        let redactedOutput = Self.redact(sanitizedOutput, secrets: secrets)
        let recentOutput = Self.boundedRecentOutput(redactedOutput, limit: Self.recentOutputLimit)
        let redactedHeader = Self.redact(headerLines.joined(separator: "\n"), secrets: secrets)
        return redactedHeader + "\n" + recentOutput + "\n"
    }

    private static func sanitizeOutput(_ output: String) -> [String] {
        guard !output.isEmpty else { return [""] }
        let normalized = output
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let rawLines = normalized.components(separatedBy: "\n")
        var sanitized: [String] = []
        var index = 0

        if let leading = consumeLeadingTruncatedJSON(rawLines) {
            sanitized.append(contentsOf: leading.filtered)
            index = leading.consumed
        }

        while index < rawLines.count {
            let line = rawLines[index]
            if let parsed = consumeJSONRecord(rawLines, startLine: index) {
                sanitized.append(contentsOf: parsed.filtered)
                index = parsed.nextLine
            } else if let orphanProperty = consumeOrphanJSONPropertyLine(line) {
                sanitized.append(contentsOf: orphanProperty)
                index += 1
            } else {
                sanitized.append(line)
                index += 1
            }
        }
        return sanitized
    }

    private static func consumeJSONRecord(_ lines: [String], startLine: Int, requireStartAtLineHead: Bool = false) -> (nextLine: Int, filtered: [String])? {
        let line = lines[startLine]
        var cursor = line.startIndex
        while cursor < line.endIndex {
            let ch = line[cursor]
            let leadingPrefix = line[..<cursor]
            if requireStartAtLineHead && !leadingPrefix.allSatisfy(\.isWhitespace) {
                return nil
            }
            let isCandidateObject = ch == "{"
            let isCandidateArray = ch == "[" && leadingPrefix.allSatisfy(\.isWhitespace)
            if isCandidateObject || isCandidateArray {
                let rawPrefix = leadingPrefix.trimmingCharacters(in: .whitespaces)
                let safePrefix = (!rawPrefix.isEmpty && !looksLikeJSONFragmentText(rawPrefix)) ? rawPrefix : nil
                let singleTail = line[cursor...].trimmingCharacters(in: .whitespaces)
                if (singleTail.hasSuffix("}") || singleTail.hasSuffix("]")),
                   let value = try? JSONSerialization.jsonObject(with: Data(singleTail.utf8)),
                   value is [String: Any] || value is [Any] {
                    return (startLine + 1, attachPrefix(safePrefix, to: serializeFiltered(value).map { [$0] } ?? []))
                }
                if let inlineSpans = consumeInlineJSONSpans(in: line, from: cursor) {
                    return (startLine + 1, attachPrefix(safePrefix, to: inlineSpans))
                }
                switch scanMultiLineJSON(lines, startLine: startLine, startIndex: cursor) {
                case .complete(let endLine, let value):
                    return (endLine + 1, attachPrefix(safePrefix, to: serializeFiltered(value).map { [$0] } ?? []))
                case .unclosedAtEOF:
                    var extracted = extractAllowedInlineFields(singleTail).map { [$0] } ?? []
                    if startLine + 1 < lines.count {
                        extracted.append(contentsOf: extractAllowedPartialFields(from: lines[(startLine + 1)...]))
                    }
                    return (lines.count, attachPrefix(safePrefix, to: extracted))
                case .notJSON:
                    if isBrokenInlineJSONStart(singleTail) {
                        let salvaged = extractAllowedInlineFields(singleTail).map { [$0] } ?? []
                        return (startLine + 1, attachPrefix(safePrefix, to: salvaged))
                    }
                    if (singleTail == "{" || singleTail == "["),
                       startLine + 1 < lines.count,
                       looksLikeIndentedJSONFragmentLine(lines[startLine + 1]) {
                        var endFrag = startLine + 1
                        while endFrag < lines.count && looksLikeIndentedJSONFragmentLine(lines[endFrag]) {
                            if consumeJSONRecord(lines, startLine: endFrag, requireStartAtLineHead: true) != nil {
                                break
                            }
                            endFrag += 1
                        }
                        let salvaged = extractAllowedPartialFields(from: lines[(startLine + 1)..<endFrag])
                        return (endFrag, attachPrefix(safePrefix, to: salvaged))
                    }
                }
            }
            cursor = line.index(after: cursor)
        }
        return nil
    }

    private static func attachPrefix(_ prefix: String?, to items: [String]) -> [String] {
        guard let prefix, !prefix.isEmpty else { return items }
        guard let first = items.first else { return [prefix] }
        return [prefix + " " + first] + Array(items.dropFirst())
    }

    private static func isBrokenInlineJSONStart(_ text: String) -> Bool {
        if text.hasPrefix("{\"") { return true }
        if text.hasPrefix("{") && text.contains("\":") { return true }
        if text.hasPrefix("[") {
            let inner = text.dropFirst().trimmingCharacters(in: .whitespaces)
            if inner.hasPrefix("{") || inner.hasPrefix("\"") { return true }
        }
        return false
    }

    private static func looksLikeJSONFragmentText(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return false }
        if trimmed.contains("\":") || trimmed.hasPrefix("{") || trimmed.hasPrefix("[") || trimmed.hasSuffix("}") || trimmed.hasSuffix("]") {
            return true
        }
        if trimmed.hasPrefix(",") || trimmed.hasSuffix("\",") {
            return true
        }
        return false
    }

    private static func consumeInlineJSONSpans(in line: String, from firstCandidate: String.Index) -> [String]? {
        var matchedAny = false
        var outputs: [String] = []
        var cursor = firstCandidate
        var plainStart = firstCandidate

        while cursor < line.endIndex {
            let ch = line[cursor]
            if ch == "{" || (ch == "[" && cursor == firstCandidate && line[..<cursor].allSatisfy(\.isWhitespace)),
               let endPos = findBalancedJSONEnd(in: line, from: cursor),
               let value = try? JSONSerialization.jsonObject(with: Data(line[cursor...endPos].utf8)),
               value is [String: Any] || value is [Any] {
                let between = line[plainStart..<cursor].trimmingCharacters(in: .whitespaces)
                if matchedAny && !between.isEmpty {
                    if looksLikeJSONFragmentText(between) {
                        if let salvaged = extractAllowedInlineFields(between) { outputs.append(salvaged) }
                    } else {
                        outputs.append(between)
                    }
                }
                if let filtered = serializeFiltered(value) { outputs.append(filtered) }
                matchedAny = true
                cursor = line.index(after: endPos)
                plainStart = cursor
                continue
            }
            cursor = line.index(after: cursor)
        }

        guard matchedAny else { return nil }
        let trailing = line[plainStart...].trimmingCharacters(in: .whitespaces)
        if !trailing.isEmpty {
            if looksLikeJSONFragmentText(trailing) {
                if let salvaged = extractAllowedInlineFields(trailing) { outputs.append(salvaged) }
            } else {
                outputs.append(trailing)
            }
        }
        return outputs
    }

    private static func findBalancedJSONEnd(in line: String, from start: String.Index) -> String.Index? {
        var stack: [Character] = []
        var inString = false
        var escaped = false
        var pos = start
        while pos < line.endIndex {
            let ch = line[pos]
            if inString {
                if escaped { escaped = false }
                else if ch == "\\" { escaped = true }
                else if ch == "\"" { inString = false }
            } else {
                if ch == "\"" { inString = true }
                else if ch == "{" || ch == "[" { stack.append(ch) }
                else if ch == "}" {
                    guard stack.popLast() == "{" else { return nil }
                    if stack.isEmpty { return pos }
                } else if ch == "]" {
                    guard stack.popLast() == "[" else { return nil }
                    if stack.isEmpty { return pos }
                } else if !isAllowedOutsideJSONString(ch) {
                    return nil
                }
            }
            pos = line.index(after: pos)
        }
        return nil
    }

    private static func consumeOrphanJSONPropertyLine(_ line: String) -> [String]? {
        var trimmed = line.trimmingCharacters(in: .whitespaces)
        if ["}", "},", "]", "],"].contains(trimmed) {
            return []
        }
        if trimmed.hasPrefix("\"") && trimmed.hasSuffix("\",") && !trimmed.contains("\":") {
            let literal = String(trimmed.dropLast())
            if (try? JSONSerialization.jsonObject(with: Data(("[" + literal + "]").utf8))) != nil {
                return []
            }
        }
        guard trimmed.hasPrefix("\""), trimmed.contains("\":") else { return nil }
        if trimmed.hasSuffix(",") { trimmed.removeLast() }
        let candidate = "{" + trimmed + "}"
        guard let dict = (try? JSONSerialization.jsonObject(with: Data(candidate.utf8))) as? [String: Any],
              dict.count == 1 else {
            if let salvaged = extractAllowedInlineFields(trimmed) { return [salvaged] }
            return []
        }
        return serializeFiltered(dict).map { [$0] } ?? []
    }

    private enum MultiLineScanResult {
        case complete(endLine: Int, value: Any)
        case unclosedAtEOF
        case notJSON
    }

    private static func scanMultiLineJSON(_ lines: [String], startLine: Int, startIndex: String.Index) -> MultiLineScanResult {
        var stack: [Character] = []
        var inString = false
        var escaped = false

        for lineIndex in startLine..<lines.count {
            let current = lines[lineIndex]
            var pos = lineIndex == startLine ? startIndex : current.startIndex
            while pos < current.endIndex {
                let ch = current[pos]
                if inString {
                    if escaped {
                        escaped = false
                    } else if ch == "\\" {
                        escaped = true
                    } else if ch == "\"" {
                        inString = false
                    }
                } else {
                    if ch == "\"" {
                        inString = true
                    } else if ch == "{" || ch == "[" {
                        stack.append(ch)
                    } else if ch == "}" {
                        guard stack.popLast() == "{" else { return .notJSON }
                        if stack.isEmpty {
                            let trailing = current[current.index(after: pos)...]
                            guard trailing.allSatisfy(\.isWhitespace) else { return .notJSON }
                            return parseMultiLineSlice(lines, startLine: startLine, startIndex: startIndex, endLine: lineIndex, endPos: pos)
                        }
                    } else if ch == "]" {
                        guard stack.popLast() == "[" else { return .notJSON }
                        if stack.isEmpty {
                            let trailing = current[current.index(after: pos)...]
                            guard trailing.allSatisfy(\.isWhitespace) else { return .notJSON }
                            return parseMultiLineSlice(lines, startLine: startLine, startIndex: startIndex, endLine: lineIndex, endPos: pos)
                        }
                    } else if !isAllowedOutsideJSONString(ch) {
                        return .notJSON
                    }
                }
                pos = current.index(after: pos)
            }
            if inString {
                return .notJSON
            }
        }
        return stack.isEmpty ? .notJSON : .unclosedAtEOF
    }

    private static func parseMultiLineSlice(_ lines: [String], startLine: Int, startIndex: String.Index, endLine: Int, endPos: String.Index) -> MultiLineScanResult {
        var chunks: [String] = []
        chunks.reserveCapacity(endLine - startLine + 1)
        for i in startLine...endLine {
            if i == startLine && i == endLine {
                chunks.append(String(lines[i][startIndex...endPos]))
            } else if i == startLine {
                chunks.append(String(lines[i][startIndex...]))
            } else if i == endLine {
                chunks.append(String(lines[i][...endPos]))
            } else {
                chunks.append(lines[i])
            }
        }
        let combined = chunks.joined(separator: "\n")
        guard let value = try? JSONSerialization.jsonObject(with: Data(combined.utf8)),
              value is [String: Any] || value is [Any] else {
            return .notJSON
        }
        return .complete(endLine: endLine, value: value)
    }

    private static func isAllowedOutsideJSONString(_ ch: Character) -> Bool {
        if ch.isWhitespace { return true }
        switch ch {
        case ":", ",", "-", "+", ".", "0"..."9", "t", "r", "u", "e", "f", "a", "l", "s", "n", "E":
            return true
        default:
            return false
        }
    }

    private static func consumeLeadingTruncatedJSON(_ lines: [String]) -> (consumed: Int, filtered: [String])? {
        guard let first = lines.first, !first.isEmpty else { return nil }
        let firstTrimmed = first.trimmingCharacters(in: .whitespaces)
        if (firstTrimmed.hasPrefix("{") || firstTrimmed.hasPrefix("[")),
           consumeJSONRecord(lines, startLine: 0, requireStartAtLineHead: true) != nil {
            return nil
        }

        if !firstTrimmed.hasPrefix("{") && !firstTrimmed.hasPrefix("[") &&
           (firstTrimmed.hasSuffix("}") || firstTrimmed.hasSuffix("]")) {
            var pos = firstTrimmed.startIndex
            while pos < firstTrimmed.endIndex {
                if firstTrimmed[pos] == "\"" {
                    let prevIndex = pos > firstTrimmed.startIndex ? firstTrimmed.index(before: pos) : nil
                    let prev = prevIndex.map { firstTrimmed[$0] }
                    if prev == nil || prev == "," || prev == "{" || prev?.isWhitespace == true {
                        let candidate = "{" + String(firstTrimmed[pos...])
                        if let dict = (try? JSONSerialization.jsonObject(with: Data(candidate.utf8))) as? [String: Any] {
                            var merged: [String: Any] = [:]
                            if let headFiltered = extractAllowedInlineDict(String(firstTrimmed[..<pos])) {
                                for (k, v) in headFiltered { merged[k] = v }
                            }
                            if let tailFiltered = filterJSON(dict) as? [String: Any] {
                                for (k, v) in tailFiltered { merged[k] = v }
                            }
                            return (1, serializeFiltered(merged).map { [$0] } ?? [])
                        }
                    }
                }
                pos = firstTrimmed.index(after: pos)
            }
            if looksLikeTruncatedSingleLineJSONTail(firstTrimmed) {
                return (1, extractAllowedInlineFields(firstTrimmed).map { [$0] } ?? [])
            }
        }

        let scanLimit = min(lines.count, 2048)
        var depth = 0
        var minDepth = 0
        var deepestCloseLine: Int?
        for lineIndex in 0..<scanLimit {
            let current = lines[lineIndex]
            guard looksLikeIndentedJSONFragmentLine(current) else { break }
            var inString = false
            var escaped = false
            for ch in current {
                if inString {
                    if escaped { escaped = false }
                    else if ch == "\\" { escaped = true }
                    else if ch == "\"" { inString = false }
                } else {
                    if ch == "\"" { inString = true }
                    else if ch == "{" || ch == "[" { depth += 1 }
                    else if ch == "}" || ch == "]" {
                        depth -= 1
                        if depth < minDepth {
                            minDepth = depth
                            deepestCloseLine = lineIndex
                        }
                    }
                }
            }
        }
        if let endLine = deepestCloseLine {
            for propLine in 0...endLine {
                let propTrimmed = lines[propLine].trimmingCharacters(in: .whitespaces)
                if propTrimmed.hasPrefix("\"") {
                    let candidate = "{\n" + lines[propLine...endLine].joined(separator: "\n")
                    if let dict = (try? JSONSerialization.jsonObject(with: Data(candidate.utf8))) as? [String: Any] {
                        var kept = extractAllowedPartialFields(from: lines[0..<propLine])
                        if let tail = serializeFiltered(dict) { kept.append(tail) }
                        return (endLine + 1, kept)
                    }
                }
            }
            return (endLine + 1, extractAllowedPartialFields(from: lines[0...endLine]))
        }
        return nil
    }

    private static func extractAllowedInlineDict(_ text: String) -> [String: Any]? {
        var found: [String: Any] = [:]
        for field in allowedFields {
            let needle = "\"\(field)\""
            var searchRange = text.startIndex..<text.endIndex
            while let keyRange = text.range(of: needle, range: searchRange) {
                searchRange = keyRange.upperBound..<text.endIndex
                var cursor = keyRange.upperBound
                while cursor < text.endIndex && text[cursor].isWhitespace { cursor = text.index(after: cursor) }
                guard cursor < text.endIndex, text[cursor] == ":" else { continue }
                cursor = text.index(after: cursor)
                while cursor < text.endIndex && text[cursor].isWhitespace { cursor = text.index(after: cursor) }
                guard cursor < text.endIndex, let valueEnd = scanJSONPrimitiveEnd(in: text, from: cursor) else { continue }
                let snippet = "{\(needle):\(text[cursor..<valueEnd])}"
                if let dict = (try? JSONSerialization.jsonObject(with: Data(snippet.utf8))) as? [String: Any],
                   let val = dict[field],
                   val is String || val is NSNumber || val is NSNull {
                    found[field] = val
                }
            }
        }
        return found.isEmpty ? nil : found
    }

    private static func extractAllowedInlineFields(_ text: String) -> String? {
        guard let dict = extractAllowedInlineDict(text) else { return nil }
        return serializeFiltered(dict)
    }

    private static func scanJSONPrimitiveEnd(in text: String, from start: String.Index) -> String.Index? {
        let first = text[start]
        if first == "\"" {
            var escaped = false
            var pos = text.index(after: start)
            while pos < text.endIndex {
                let ch = text[pos]
                if escaped { escaped = false }
                else if ch == "\\" { escaped = true }
                else if ch == "\"" { return text.index(after: pos) }
                pos = text.index(after: pos)
            }
            return nil
        }
        var pos = start
        while pos < text.endIndex {
            let ch = text[pos]
            if ch == "," || ch == "}" || ch == "]" || ch.isWhitespace { break }
            pos = text.index(after: pos)
        }
        return pos > start ? pos : nil
    }

    private static func looksLikeTruncatedSingleLineJSONTail(_ text: String) -> Bool {
        guard !text.contains("{") else { return false }
        if text.hasSuffix("\"}") || text.hasSuffix("\"]") {
            var unescapedQuotes = 0
            var escaped = false
            for ch in text {
                if escaped { escaped = false }
                else if ch == "\\" { escaped = true }
                else if ch == "\"" { unescapedQuotes += 1 }
            }
            if unescapedQuotes % 2 == 1 { return true }
        }
        if text.contains("\":") && (text.hasSuffix("}") || text.hasSuffix("]")) {
            return true
        }
        return false
    }

    private static func looksLikeIndentedJSONFragmentLine(_ line: String) -> Bool {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return false }
        if ["}", "},", "]", "],", "{", "["].contains(trimmed) { return true }
        if trimmed.contains("\":") { return true }
        if trimmed.hasSuffix("\",") || trimmed.hasSuffix("\"") { return true }
        return trimmed.allSatisfy { isAllowedOutsideJSONString($0) || $0 == "{" || $0 == "}" || $0 == "[" || $0 == "]" }
    }

    private static func extractAllowedPartialFields(from slice: ArraySlice<String>) -> [String] {
        var extracted: [String: Any] = [:]
        for line in slice {
            var trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("\"") else { continue }
            if trimmed.hasSuffix(",") { trimmed.removeLast() }
            let candidate = "{" + trimmed + "}"
            if let dict = (try? JSONSerialization.jsonObject(with: Data(candidate.utf8))) as? [String: Any] {
                for (key, value) in dict where allowedFields.contains(key) {
                    if value is String || value is NSNumber || value is NSNull {
                        extracted[key] = value
                    }
                }
            }
        }
        guard !extracted.isEmpty, let serialized = serializeFiltered(extracted) else { return [] }
        return [serialized]
    }

    private static func filterJSON(_ value: Any) -> Any? {
        if let dict = value as? [String: Any] {
            var filtered: [String: Any] = [:]
            for (key, item) in dict where allowedFields.contains(key) {
                if item is String || item is NSNumber || item is NSNull {
                    filtered[key] = item
                } else if let nested = filterJSON(item) {
                    filtered[key] = nested
                }
            }
            return filtered.isEmpty ? nil : filtered
        }
        if let array = value as? [Any] {
            let items = array.compactMap(filterJSON)
            return items.isEmpty ? nil : items
        }
        return nil
    }

    private static func serializeFiltered(_ value: Any) -> String? {
        guard let filtered = filterJSON(value),
              JSONSerialization.isValidJSONObject(filtered),
              let bytes = try? JSONSerialization.data(withJSONObject: filtered, options: [.sortedKeys, .withoutEscapingSlashes]),
              let text = String(data: bytes, encoding: .utf8) else {
            return nil
        }
        return text
    }

    private static func boundedRecentOutput(_ text: String, limit: Int) -> String {
        guard text.count > limit else { return text }
        let lines = text.components(separatedBy: "\n")
        var kept: [String] = []
        var total = 0
        for line in lines.reversed() {
            let separator = kept.isEmpty ? 0 : 1
            if total + separator + line.count <= limit {
                kept.append(line)
                total += separator + line.count
            } else {
                if kept.isEmpty {
                    return String(line.suffix(limit))
                }
                break
            }
        }
        return kept.reversed().joined(separator: "\n")
    }

    private static func secretVariants(for secrets: [String]) -> [String] {
        var variants = Set<String>()
        for secret in secrets where !secret.isEmpty {
            variants.insert(secret)
            if let encoded = try? JSONSerialization.data(withJSONObject: [secret], options: [.withoutEscapingSlashes]),
               let text = String(data: encoded, encoding: .utf8),
               text.count >= 4 {
                let inner = String(text.dropFirst(2).dropLast(2))
                if !inner.isEmpty {
                    variants.insert(inner)
                    variants.insert(inner.replacingOccurrences(of: "/", with: #"\/"#))
                }
            }
        }
        return variants.sorted { $0.count > $1.count }
    }

    private static func decodePrintableASCIIUnicodeEscapes(_ text: String) -> String {
        guard text.contains("\\u00") || text.contains("\\U00") else { return text }
        var output = ""
        output.reserveCapacity(text.count)
        var cursor = text.startIndex
        while cursor < text.endIndex {
            if text[cursor] == "\\",
               let uPos = text.index(cursor, offsetBy: 1, limitedBy: text.endIndex),
               uPos < text.endIndex, (text[uPos] == "u" || text[uPos] == "U"),
               let hexEnd = text.index(cursor, offsetBy: 6, limitedBy: text.endIndex) {
                let hex = text[text.index(cursor, offsetBy: 2)..<hexEnd]
                if hex.count == 4, let code = UInt8(hex, radix: 16), code >= 0x20 && code <= 0x7E {
                    if code == 0x22 {
                        output += #"\""#
                    } else if code == 0x5C {
                        output += #"\\"#
                    } else {
                        output.append(Character(UnicodeScalar(code)))
                    }
                    cursor = hexEnd
                    continue
                }
            }
            output.append(text[cursor])
            cursor = text.index(after: cursor)
        }
        return output
    }

    private static func redact(_ text: String, secrets: [String]) -> String {
        var result = decodePrintableASCIIUnicodeEscapes(text)
        for secret in secretVariants(for: secrets) {
            result = result.replacingOccurrences(of: secret, with: "[已隐藏]")
        }
        let home = NSHomeDirectory()
        if !home.isEmpty && home != "/" {
            let escapedSlashHome = home.replacingOccurrences(of: "/", with: #"\/"#)
            let homePatterns = [
                NSRegularExpression.escapedPattern(for: escapedSlashHome) + #"(?=$|\\/|/|[\s\"'\\<>),;:])"#,
                NSRegularExpression.escapedPattern(for: home) + #"(?=$|/|\\/|[\s\"'\\<>),;:])"#
            ]
            for pattern in homePatterns {
                result = result.replacingOccurrences(of: pattern, with: "~", options: .regularExpression)
            }
            result = result.replacingOccurrences(of: #"~\/"#, with: "~/")
        }
        let replacements = [
            (#"https?:(?://|\\/\\/)(?:\\/|[^\s\"'\\<>])+"#, "[URL]"),
            (#"(?:\\/|/)Users(?:\\/|/)[^/\\\s\"'<>]+"#, "/Users/[用户]"),
            (#"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"#, "[邮箱]"),
            (#"(?i)(password|passphrase|passwordtoken|token|authorization|cookie|verificationcode|dsid|appleid|apple_id)(?:\\\"|\"|')?\s*[=:]\s*(?:\\\"(?:\\\\\\\"|\\\\|\\[^\"\\]|[^\"\\])*\\\"|\"(?:\\.|[^\"\\])*\"|'[^']*'|[^\s,;\"'\\}]+)"#, "$1=[已隐藏]"),
            (#"(?<![0-9])\+?[0-9]{10,15}(?![0-9])"#, "[编号]")
        ]
        for (pattern, replacement) in replacements {
            result = result.replacingOccurrences(of: pattern, with: replacement, options: .regularExpression)
        }
        return result
    }
}
