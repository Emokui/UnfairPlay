import Foundation
import CryptoKit
import Darwin
import Security

@main struct Tests {
    static func model(_ url: URL, seed: UInt8 = 0) throws {
        var bytes = Data("FPSENR2\0".utf8)
        for value: UInt32 in [2, 32] { bytes.append(contentsOf: (0..<4).map { UInt8((value >> ($0 * 8)) & 255) }) }
        bytes.append(Data(repeating: seed, count: 16))
        try bytes.write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
    static func validModel(_ url: URL) throws {
        var data = Data(repeating: 0, count: 4184)
        data.replaceSubrange(0..<8, with: Data("FPSENR2\0".utf8))
        for (offset, value) in [(8, UInt32(2)), (12, UInt32(4184))] {
            for n in 0..<4 { data[offset+n] = UInt8((value >> (n*8)) & 255) }
        }
        for table in 0..<16 { for value in 0..<256 { data[88+table*256+value] = UInt8(value) } }
        try data.write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
    @MainActor static func waitUntil(_ message: String = "timed out", _ condition: () -> Bool) async {
        for _ in 0..<150 { if condition() { return }; try? await Task.sleep(nanoseconds: 100_000_000) }
        preconditionFailure(message)
    }
    @MainActor static func main() async throws {
        setbuf(stdout, nil)
        if CommandLine.arguments.count > 2 && CommandLine.arguments[1] == "--inspect-model" {
            _ = try Core.modelFiles(URL(fileURLWithPath: CommandLine.arguments[2])); print("PASS: genuine existing model header, length, version and private permissions"); return
        }
        if CommandLine.arguments.count > 2 && CommandLine.arguments[1] == "--orphan" {
            let runner = Runner()
            runner.launch(URL(fileURLWithPath: "/bin/zsh"), ["-c", "/bin/sleep 2; printf bad > \"$1\"", "worker", CommandLine.arguments[2]], title: "orphan test")
            try? await Task.sleep(nanoseconds: 150_000_000)
            exit(0)
        }
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("desk-regressions-" + UUID().uuidString).resolvingSymlinksInPath()
        try Core.privateDirectory(root)
        defer { try? fm.removeItem(at: root) }
        precondition(DownloadedIPA.versionForFilename("未知版本", versionID: "123") == "版本ID-123")
        precondition(DownloadedIPA.versionForFilename("  未知版本  ", versionID: "124") == "版本ID-124")
        precondition(DownloadedIPA.versionForFilename("", versionID: "125") == "版本ID-125")
        precondition(DownloadedIPA.versionForFilename(nil, versionID: "") == nil)
        precondition(DownloadedIPA.versionForFilename("2.4", versionID: "123") == "2.4")
        precondition(DownloadedIPA.filename(for: "Synthetic/App", noUpdate: false, version: "2.4") == "Synthetic App_2.4.ipa")
        precondition(DownloadedIPA.filename(for: "Synthetic", noUpdate: true, version: "2.4") == "Synthetic_2.4_no-update.ipa")
        let legacyDownload = try JSONDecoder().decode(DownloadedIPA.self, from: Data(#"{"url":"file:///tmp/synthetic.ipa","appName":"Synthetic"}"#.utf8))
        precondition(legacyDownload.accountID == nil && legacyDownload.stamp == nil)
        let occupied = root.appendingPathComponent("Synthetic_2.4.ipa")
        try Data().write(to: occupied)
        let unused = try DownloadedIPA.unusedTarget(named: occupied.lastPathComponent, in: root)
        precondition(unused.url.lastPathComponent == "Synthetic_2.4-2.ipa" && unused.original == nil)
        let sourceStamp = try Core.fileStamp(occupied)
        let downloadRecord = DownloadedIPA(url: occupied, appName: "Synthetic", accountID: UUID(), version: "2.4", stamp: sourceStamp)
        let decodedRecord = try JSONDecoder().decode(DownloadedIPA.self, from: JSONEncoder().encode(downloadRecord))
        precondition(decodedRecord.accountID == downloadRecord.accountID && decodedRecord.stamp == sourceStamp)
        let metadata = try JSONDecoder().decode(IPAMetadata.self, from: Data(#"{"path":"/tmp/synthetic.ipa","status":"encrypted","name":"Synthetic","bundle_id":"example.synthetic","version":"2.4","bytes":123,"selector_ids":["00000001:00000002"],"selector_scan_complete":true}"#.utf8))
        precondition(metadata.bundleID == "example.synthetic" && metadata.selectorScanComplete == true && metadata.status == .encrypted)
        let hintProfile = Profile(id: UUID(), name: "Synthetic")
        func hint(_ selectors: Set<String>, state: ModelCheckState?) -> IPAModelHint? {
            IPAModelHint.resolve(metadata, profiles: [hintProfile], selected: hintProfile.id,
                                 selectors: [hintProfile.id: selectors], states: state.map { [hintProfile.id: $0] } ?? [:])
        }
        precondition(hint([], state: nil)?.text == "正在校验模型…")
        precondition(hint([], state: .checking)?.text == "正在校验模型…")
        precondition(hint([], state: .valid)?.text == "模型关联待确认")
        precondition(hint([], state: .invalid)?.text == "尚未找到匹配模型")
        precondition(hint(["00000001:00000002"], state: .valid)?.text == "当前档案模型匹配")
        let incompleteMetadata = try JSONDecoder().decode(IPAMetadata.self, from: Data(#"{"path":"/tmp/synthetic.ipa","status":"encrypted","selector_ids":["00000001:00000002"],"selector_scan_complete":false}"#.utf8))
        precondition(IPAModelHint.resolve(incompleteMetadata, profiles: [hintProfile], selected: hintProfile.id,
                                         selectors: [:], states: [hintProfile.id: .invalid])?.text == "许可信息未确认")
        if let sourceStamp {
            let savedEntry = IPAStatusEntry(stamp: sourceStamp, metadata: metadata, icon: nil).saved(at: occupied, stamp: sourceStamp)
            precondition(savedEntry.metadata.path == occupied.path && savedEntry.stamp == sourceStamp && savedEntry.metadata.version == "2.4")
        }
        let scanDirectory = root.appendingPathComponent("scan-files")
        try Core.privateDirectory(scanDirectory)
        let scanFile = scanDirectory.appendingPathComponent("cached.ipa")
        try Data("synthetic".utf8).write(to: scanFile)
        let scanStamp = try Core.fileStamp(scanFile)!
        let scanEntry = IPAStatusEntry(stamp: scanStamp, metadata: metadata, icon: nil).saved(at: scanFile, stamp: scanStamp)
        var scanCache = [scanFile: scanEntry]
        let scanRequest = IPAFolderScan(folder: scanDirectory, revision: 1, additionalFiles: [], selection: [])
        let selectedRequest = IPAFolderScan(folder: scanDirectory, revision: 1, additionalFiles: [], selection: [scanFile])
        precondition(scanRequest == selectedRequest)
        var enumerated = false
        var scanCalls = 0
        let lateFile = root.appendingPathComponent("new-download.ipa")
        try Data("new".utf8).write(to: lateFile)
        let lateStamp = try Core.fileStamp(lateFile)!
        let lateEntry = IPAStatusEntry(stamp: lateStamp, metadata: metadata, icon: nil).saved(at: lateFile, stamp: lateStamp)
        await scanRequest.run(cache: { scanCache }, listed: { result in
            precondition((try? result.get()) == [scanFile]); enumerated = true
        }, apply: { scanCache = $0 }, read: { files, baseline in
            scanCalls += 1
            precondition(enumerated && files == [scanFile] && baseline[scanFile]?.stamp == scanStamp)
            scanCache[lateFile] = lateEntry
            return baseline
        })
        precondition(scanCalls == 1 && scanCache[scanFile]?.stamp == scanStamp && scanCache[lateFile]?.stamp == lateStamp)
        let importedRequest = IPAFolderScan(folder: scanDirectory, revision: 1, additionalFiles: [lateFile], selection: [])
        precondition(importedRequest != scanRequest)
        await importedRequest.run(cache: { scanCache }, listed: { _ in }, apply: { scanCache = $0 }, read: { files, baseline in
            precondition(Set(files) == [scanFile, lateFile])
            try! Data("changed file".utf8).write(to: scanFile)
            let freshStamp = try! Core.fileStamp(scanFile)!
            scanCache[scanFile] = scanEntry.saved(at: scanFile, stamp: freshStamp)
            return [scanFile: scanEntry]
        })
        precondition(scanCache[scanFile]?.stamp == (try! Core.fileStamp(scanFile)))
        var resumeScan: CheckedContinuation<[URL: IPAStatusEntry], Never>?
        var cancelledScanApplied = false
        let cancelledScan = Task { @MainActor in
            await importedRequest.run(cache: { scanCache }, listed: { _ in }, apply: { _ in cancelledScanApplied = true }, read: { _, _ in
                await withCheckedContinuation { resumeScan = $0 }
            })
        }
        await waitUntil { resumeScan != nil }
        cancelledScan.cancel()
        resumeScan?.resume(returning: [:])
        await cancelledScan.value
        precondition(!cancelledScanApplied && scanCache[lateFile] != nil)
        print("PASS: sequential directory scan, saved/external cache reuse, stale-result preservation and scan cancellation")

        let reportDirectory = root.appendingPathComponent("report-fixture/Reports")
        try Core.privateDirectory(reportDirectory)
        let reportInput = root.appendingPathComponent("synthetic-input.ipa")
        let reportOutput = root.appendingPathComponent("synthetic-result.ipa")
        let inputBytes = Data("synthetic-encrypted-input".utf8)
        let outputBytes = Data("synthetic-decrypted-output".utf8)
        try inputBytes.write(to: reportInput)
        try outputBytes.write(to: reportOutput)
        let inputSHA = SHA256.hash(data: inputBytes).map { String(format: "%02x", $0) }.joined()
        let outputSHA = SHA256.hash(data: outputBytes).map { String(format: "%02x", $0) }.joined()
        let reportJSON: [String: Any] = [
            "input": ["path": reportInput.path, "sha256": inputSHA],
            "output": ["path": reportOutput.path, "sha256": outputSHA],
            "complete": true, "plaintext_verified": false,
            "images": [["member": "Payload/Test.app/Test", "first_page_audit": "arm64-instruction-decode"]]
        ]
        try Core.writeJSON(reportJSON, to: reportDirectory.appendingPathComponent("synthetic.json"))
        let reportRoot = reportDirectory.deletingLastPathComponent()
        let savedReport = try IPASavedReport.find(for: reportOutput, root: reportRoot)
        precondition(savedReport.document.output.sha256 == outputSHA)
        precondition(savedReport.document.images?.first?.auditDescription == "ARM64 指令结构审计")
        let savedInputReport = try IPASavedReport.find(for: reportInput, root: reportRoot)
        precondition(savedInputReport.url == savedReport.url)
        let movedReportOutput = root.appendingPathComponent("moved-archive-result.ipa")
        try outputBytes.write(to: movedReportOutput)
        let movedReport = try IPASavedReport.find(for: movedReportOutput, root: reportRoot)
        precondition(movedReport.url == savedReport.url && movedReport.document.output.sha256 == outputSHA)
        try Data("overwritten-different-ipa".utf8).write(to: reportOutput)
        do {
            _ = try IPASavedReport.find(for: reportOutput, root: reportRoot)
            preconditionFailure("must reject stale report when IPA SHA-256 no longer matches")
        } catch {
            precondition(error.localizedDescription.contains("匹配"))
        }
        try inputBytes.write(to: reportOutput)
        do {
            _ = try IPASavedReport.find(for: reportOutput, root: reportRoot)
            preconditionFailure("must reject output path whose bytes no longer match output SHA-256")
        } catch {
            precondition(error.localizedDescription.contains("匹配"))
        }
        do {
            _ = try IPASavedReport.find(for: root.appendingPathComponent("nonexistent-report-target.ipa"), root: reportRoot)
            preconditionFailure("must reject nonexistent IPA when looking up report")
        } catch {}
        precondition(Core.appID("https://apps.apple.com/jp/app/test/id6474479684?l=ja") == "6474479684")
        precondition(Core.appID("6474479684") == "6474479684")
        precondition(Core.appID("https://evil.example/id123") == nil && Core.appID("0") == nil)
        precondition(UpdateChecker.isNewer("v1.5.8", than: "1.5.8-beta.2"))
        precondition(UpdateChecker.isNewer("v1.6.0", than: "1.5.8"))
        precondition(!UpdateChecker.isNewer("v1.5.7", than: "1.5.8-beta.2"))
        precondition(!UpdateChecker.isNewer("v1.5.8", than: "1.5.8"))
        precondition(!UpdateChecker.isNewer("", than: "1.5.8"))
        precondition(!UpdateChecker.isNewer("1.5.bad.9", than: "1.5.8"))
        let history = try CatalogService.parseHistory(Data(#"[{"external_identifier":868540902,"bundle_version":"1.2.9"},{"external_identifier":"868540902","bundle_version":"duplicate"},{"external_identifier":"12x","bundle_version":"invalid"},{"versionId":"868540901","version":"1.2.8"}]"#.utf8))
        precondition(history.map(\.id) == ["868540902", "868540901"])
        precondition(history.first?.version == "1.2.9")
        let wrapped = try CatalogService.parseHistory(Data(#"{"data":[{"version_id":"123","version":"2.0","date":"2024-01-01"}]}"#.utf8))
        precondition(wrapped.first?.date == "2024-01-01")
        precondition(DownloadCatalog.country(forStoreFront: "143462-1,32") == "JP")
        precondition(DownloadCatalog.country(forStoreFront: " 143465,29 ") == "CN")
        precondition(DownloadCatalog.country(forStoreFront: "143443") == "DE")
        precondition(DownloadCatalog.country(forStoreFront: "143444") == "GB")
        precondition(DownloadCatalog.country(forStoreFront: "143463") == "HK")
        precondition(DownloadCatalog.country(forStoreFront: "143470") == "TW")
        precondition(DownloadCatalog.country(forStoreFront: "143466") == "KR")
        precondition(DownloadCatalog.country(forStoreFront: nil) == "US")
        precondition(DownloadCatalog.country(forStoreFront: "143442") == "FR")
        precondition(DownloadCatalog.country(forStoreFront: "unknown") == "US")
        precondition(Core.storeFront(in: #"{"success":false,"email":"test@example.com","storeFront":"143462"}"#) == nil)
        precondition(Core.storeFront(in: #"{"success":true,"email":"test@example.com","storeFront":"143462-1,32"}"#) == "143462-1,32")
        precondition(Core.storeFront(in: #"{"sessionRefreshed":true,"email":"test@example.com","storeFront":"143462-1,32"}"#) == "143462-1,32")
        let refreshedSession = Core.refreshedSession(in: #"{"sessionRefreshed":true,"email":" Test@Example.com ","storeFront":"143462-1,32"}"# + "\n" + #"{"level":"error","error":"license is required"}"#)
        precondition(refreshedSession?.email == "test@example.com" && refreshedSession?.storeFront == "143462-1,32")
        precondition(Core.refreshedSession(in: #"{"sessionRefreshed":false,"email":"test@example.com"}"#) == nil)
        precondition(Core.refreshedSession(in: #"{"sessionRefreshed":true,"email":"   "}"#) == nil)
        precondition(Core.email(in: #"{"sessionRefreshed":true,"email":"test@example.com"}"#) == nil)
        let iosdump = try CatalogService.parseHistory(Data(#"{"code":200,"total":1,"data":[{"bundle_version":"1.4.2","external_identifier":894154892,"created_at":"2026-10-30 19:32:28"}]}"#.utf8))
        precondition(iosdump.first?.id == "894154892" && iosdump.first?.version == "1.4.2")
        precondition(VersionSource.allCases.map(\.rawValue) == ["Timbrd", "Bilin", "iOSDump"])
        let catalog = DownloadCatalog()
        catalog.selectApp("123"); catalog.selectedVersion = "456"
        precondition(catalog.versionArguments == ["--external-version-id", "456"])
        catalog.selectApp("789")
        precondition(catalog.versionArguments.isEmpty && catalog.versions.isEmpty)
        catalog.versions = iosdump
        catalog.versionsLoaded = true
        catalog.purchaseStatus["789"] = .owned
        catalog.selectedVersion = "--output"
        precondition(!catalog.validVersion)
        catalog.changeAccount()
        precondition(catalog.validVersion && catalog.selectedVersion.isEmpty)
        precondition(catalog.versionsLoaded && catalog.versions.map(\.id) == iosdump.map(\.id) && catalog.purchaseStatus.isEmpty)
        catalog.selectCountry("JP")
        precondition(catalog.country == "JP" && catalog.versionsLoaded && catalog.versions.map(\.id) == iosdump.map(\.id))
        let version = try DownloadCatalog.response(CatalogVersion.self, in: "progress\n" + #"{"externalVersionID":"123","displayVersion":"1.0","releaseDate":"2024-01-01T12:00:00Z"}"#)
        precondition(version.displayVersion == "1.0" && version.dateText != nil)
        print("PASS: version catalog formats, deduplication, app/account isolation, exact download version arguments and mixed CLI output")
        let runner = Runner()
        let unlaunched = root.appendingPathComponent("must-not-launch")
        let preparing = Runner(verify: { try await Task.sleep(nanoseconds: 150_000_000) })
        let cancelledBeforeLaunch = Task { @MainActor in
            await withCheckedContinuation { continuation in
                preparing.launch(URL(fileURLWithPath: "/usr/bin/touch"), [unlaunched.path], title: "prepare") { continuation.resume(returning: $0) }
            }
        }
        await waitUntil { preparing.busy }
        precondition(preparing.process == nil && !preparing.canReply && Runner.active[preparing.id] != nil)
        preparing.stop()
        let cancelledResult = await cancelledBeforeLaunch.value
        precondition(!cancelledResult)
        precondition(!fm.fileExists(atPath: unlaunched.path) && Runner.active[preparing.id] == nil)
        let rejected = Runner(verify: { throw DeskError("synthetic signature rejection") })
        let rejectedLaunch = await withCheckedContinuation { continuation in
            rejected.launch(URL(fileURLWithPath: "/usr/bin/touch"), [unlaunched.path], title: "reject") { continuation.resume(returning: $0) }
        }
        precondition(!rejectedLaunch && !rejected.busy && rejected.process == nil && Runner.active[rejected.id] == nil)
        precondition(!fm.fileExists(atPath: unlaunched.path) && rejected.hint == "synthetic signature rejection")
        print("PASS: preparation remains tracked, cancellation prevents process launch, verification failure releases task and returns error")
        let ok = await withCheckedContinuation { continuation in
            runner.launch(URL(fileURLWithPath: "/bin/zsh"), ["-c", "printf 'password: '; read -r value; [[ $value == synthetic-secret ]] || exit 2; printf '\\naccepted\\n'"], title: "password") { continuation.resume(returning: $0) }
            Task { @MainActor in
                await waitUntil("timed out waiting for the synthetic shell password prompt") {
                    runner.inputPrompt == .password
                }
                runner.reply("synthetic-secret")
            }
        }
        precondition(ok && runner.output.contains("accepted") && !runner.output.contains("synthetic-secret"))
        let goInput = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("GoInputTest")
        let goInteraction = await withCheckedContinuation { continuation in
            runner.launch(goInput, [], title: "Go terminal input", sessionAccount: UUID()) { continuation.resume(returning: $0) }
            Task { @MainActor in
                await waitUntil("timed out waiting for the synthetic Go password prompt") {
                    runner.inputPrompt == .password
                }
                precondition(runner.canReply)
                runner.reply("synthetic-go-secret")
                precondition(!runner.canReply)
                await waitUntil("timed out waiting for the synthetic 2FA prompt") {
                    runner.inputPrompt == .verification
                }
                precondition(runner.canReply)
                runner.reply("123456")
            }
        }
        precondition(goInteraction && runner.output.contains("verification accepted") && !runner.canReply)
        precondition(!runner.output.contains("synthetic-go-secret") && !runner.output.contains("123456"))
        let ambiguousOutcome = await withCheckedContinuation { continuation in
            runner.launch(goInput, ["--ambiguous"], title: "Go ambiguous login") { continuation.resume(returning: $0) }
            Task { @MainActor in
                await waitUntil("timed out waiting for the ambiguous verification prompt") {
                    runner.inputPrompt == .verificationChoice
                }
                precondition(runner.canReply && runner.title == "等待确认登录")
                runner.reply("")
                precondition(!runner.canReply)
            }
        }
        precondition(!ambiguousOutcome && !runner.cancelled && !runner.canReply)
        precondition(runner.hint == "请核对 Apple 账户和密码。收到本次登录的验证码后，可以选择继续验证。")
        print("PASS: synthetic 2FA prompt recognized, six-digit code accepted without echo, ambiguous empty-code reply surfaces password guidance")
        let chained = await withCheckedContinuation { continuation in
            runner.launch(URL(fileURLWithPath: "/usr/bin/true"), [], title: "first") { first in
                precondition(first)
                runner.launch(URL(fileURLWithPath: "/usr/bin/true"), [], title: "second") { continuation.resume(returning: $0) }
            }
        }
        precondition(chained)
        let batchRunner = Runner(verify: {})
        let batchToken = batchRunner.beginBatch("synthetic batch")!
        for index in 0..<2 {
            precondition(batchRunner.busy && Runner.active[batchRunner.id] != nil)
            let child = await withCheckedContinuation { continuation in
                batchRunner.launch(URL(fileURLWithPath: "/usr/bin/true"), [], title: "batch \(index)", holdsCompletion: true, batchID: batchToken) {
                    continuation.resume(returning: $0)
                }
            }
            precondition(child && batchRunner.busy && batchRunner.saving)
            batchRunner.finishCompletion()
            precondition(batchRunner.busy && !batchRunner.saving && Runner.active[batchRunner.id] != nil)
            await Task.yield()
            precondition(batchRunner.busy)
        }
        batchRunner.finishBatch(batchToken)
        precondition(!batchRunner.busy && Runner.active[batchRunner.id] == nil)
        let cancellationToken = batchRunner.beginBatch("cancel between files")!
        batchRunner.stop()
        let blockedChild = await withCheckedContinuation { continuation in
            batchRunner.launch(URL(fileURLWithPath: "/usr/bin/touch"), [unlaunched.path], title: "cancelled batch", batchID: cancellationToken) {
                continuation.resume(returning: $0)
            }
        }
        precondition(!blockedChild && batchRunner.busy && !fm.fileExists(atPath: unlaunched.path))
        batchRunner.finishBatch(cancellationToken)
        precondition(!batchRunner.busy)
        print("PASS: batch stays tracked between files, accepts its next child and cancels before the next launch")

        let failed = await withCheckedContinuation { continuation in
            runner.launch(URL(fileURLWithPath: "/usr/bin/false"), [], title: "failure") { continuation.resume(returning: $0) }
        }
        precondition(!failed)
        let cancelled = await withCheckedContinuation { continuation in
            runner.launch(URL(fileURLWithPath: "/bin/zsh"), ["-c", "read -r value"], title: "cancel") { continuation.resume(returning: $0) }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { runner.stop() }
        }
        precondition(!cancelled && runner.cancelled)
        runner.output = ""; runner.currentLine = ""; runner.log = ""
        let chinese = Data("中文".utf8)
        runner.receive(Data(chinese.prefix(1))); runner.receive(Data(chinese.dropFirst(1)))
        precondition(runner.output == "中文")
        runner.log = ""; runner.currentLine = ""; runner.append("保留行\r"); runner.append("\n")
        precondition(runner.log == "保留行\n")
        precondition(InputPrompt.match("enter password:") == .password)
        let created = root.appendingPathComponent("worker-created")
        let privateChild = await withCheckedContinuation { continuation in
            runner.launch(URL(fileURLWithPath: "/bin/zsh"), ["-c", ": > \"$1\"", "mode", created.path], title: "mode") { continuation.resume(returning: $0) }
        }
        precondition(privateChild)
        precondition((try! fm.attributesOfItem(atPath: created.path)[.posixPermissions] as! NSNumber).intValue == 0o600)
        let orphanMarker = root.appendingPathComponent("orphan-marker")
        let parent = Process(); parent.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]); parent.arguments = ["--orphan", orphanMarker.path]
        try parent.run(); parent.waitUntilExit()
        try await Task.sleep(nanoseconds: 2_700_000_000)
        precondition(!fm.fileExists(atPath: orphanMarker.path))
        print("PASS: Go password/2FA without echo, hidden input, chained completions, failed exit, cancellation, UTF-8 streaming, worker umask, orphan-worker termination")

        let sourceDir = root.appendingPathComponent("real"), linkDir = root.appendingPathComponent("alias")
        try Core.privateDirectory(sourceDir); try fm.createSymbolicLink(at: linkDir, withDestinationURL: sourceDir)
        let input = sourceDir.appendingPathComponent("input.ipa"), alias = linkDir.appendingPathComponent("input.ipa")
        try Data("original".utf8).write(to: input)
        let temporary = root.appendingPathComponent("new.ipa"); try Data("new".utf8).write(to: temporary)
        precondition(Core.sameFile(input, alias))
        do { try Core.commit(temporary, to: alias, protecting: input); preconditionFailure("must reject source alias") } catch {}
        precondition(String(decoding: try! Data(contentsOf: input), as: UTF8.self) == "original")
        let hardlink = root.appendingPathComponent("hardlink.ipa"); try fm.linkItem(at: input, to: hardlink)
        precondition(Core.sameFile(input, hardlink))
        let output = root.appendingPathComponent("output.ipa"); try Data("old".utf8).write(to: output)
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: output.path)
        try Core.commit(temporary, to: output, protecting: input)
        precondition((try! fm.attributesOfItem(atPath: output.path)[.posixPermissions] as! NSNumber).intValue == 0o600)
        print("PASS: symlink and hardlink source protection, atomic replacement, final permissions 600")

        let newOutput = root.appendingPathComponent("appeared.ipa")
        let destination = try Core.OutputTarget(newOutput)
        try Data("result".utf8).write(to: temporary)
        try Data("external".utf8).write(to: newOutput)
        do { try destination.commit(temporary); preconditionFailure("must preserve newly appeared output") } catch {}
        precondition(try! Data(contentsOf: newOutput) == Data("external".utf8))
        let existingDestination = try Core.OutputTarget(newOutput)
        try Data("modified".utf8).write(to: newOutput)
        do { try existingDestination.commit(temporary); preconditionFailure("must preserve changed output") } catch {}
        let confirmedDestination = try Core.OutputTarget(newOutput)
        try confirmedDestination.commit(temporary)
        precondition(try! Data(contentsOf: newOutput) == Data("result".utf8))
        let absentOutput = root.appendingPathComponent("new-output.ipa")
        let absentDestination = try Core.OutputTarget(absentOutput)
        try Data("new".utf8).write(to: temporary)
        try absentDestination.commit(temporary)
        precondition(try! Data(contentsOf: absentOutput) == Data("new".utf8))
        // Exercise the no-replace rename independently of the initial state comparison.
        try Data("not saved".utf8).write(to: temporary)
        do { try Core.commit(temporary, to: absentOutput, exclusive: true); preconditionFailure("must not replace") } catch {}
        precondition(try! Data(contentsOf: absentOutput) == Data("new".utf8))
        print("PASS: changed/appeared output preserved, confirmed replacement and exclusive new output")

        // A failed save leaves the finished payload available for an immediate Save As.
        let retryOutput = root.appendingPathComponent("retry-original.ipa")
        let retryTarget = try Core.OutputTarget(retryOutput)
        let retryStage = try WorkStage.create(beside: retryOutput, root: root.appendingPathComponent("save-retry-jobs"))
        try Data("completed payload".utf8).write(to: retryStage.ipa)
        try Data("external file".utf8).write(to: retryOutput)
        do { try retryTarget.commit(retryStage.ipa); preconditionFailure("must detect changed destination") } catch {}
        precondition(fm.fileExists(atPath: retryStage.ipa.path))
        let alternate = root.appendingPathComponent("retry-saved.ipa")
        try Core.OutputTarget(alternate).commit(retryStage.ipa)
        try retryStage.cleanup()
        precondition(try! Data(contentsOf: alternate) == Data("completed payload".utf8))
        precondition(try! Data(contentsOf: retryOutput) == Data("external file".utf8))
        print("PASS: failed save retains payload for Save As without rerunning task")

        let savingTask = Task { @MainActor in
            await runner.saveFile { usleep(150_000) }
        }
        await waitUntil { runner.saving }
        precondition(runner.busy && Runner.active[runner.id] != nil)
        try await Task.sleep(nanoseconds: 10_000_000)
        precondition(runner.saving) // main actor stays responsive during disk work
        guard case .success = await savingTask.value else { preconditionFailure("save failed") }
        precondition(!runner.busy && !runner.saving && Runner.active[runner.id] == nil)
        print("PASS: file saving runs off main actor and stays tracked until completion")

        let work = Task { @MainActor in
            await runner.fileWork("synthetic model import") {
                precondition(!Thread.isMainThread)
                usleep(150_000)
                let source = root.appendingPathComponent("background-import")
                let dest = root.appendingPathComponent("background-installed")
                try Core.privateDirectory(source)
                try Self.model(source.appendingPathComponent("model.bin"))
                try Core.installModels(source, to: dest)
                let valid = Core.hasModel(dest)
                try fm.removeItem(at: source); try fm.removeItem(at: dest)
                return valid
            }
        }
        await waitUntil { runner.saving }
        try await Task.sleep(nanoseconds: 10_000_000)
        precondition(runner.busy && runner.saving && Runner.active[runner.id] != nil)
        let imported = await work.value
        precondition(try! imported.get())
        let rejectedWork: Result<Void, Error> = await runner.fileWork("synthetic failure") { throw DeskError("disk failure") }
        guard case .failure = rejectedWork else { preconditionFailure("must return disk failure") }
        precondition(!runner.busy && !runner.saving && Runner.active[runner.id] == nil)
        print("PASS: model installation and cleanup run off main thread; UI remains responsive; file work returns values and failures")

        if let volume = ProcessInfo.processInfo.environment["DESK_TEST_VOLUME"] {
            let crossSource = root.appendingPathComponent("cross-volume.ipa")
            let crossTarget = URL(fileURLWithPath: volume).appendingPathComponent("cross-\(UUID().uuidString).ipa")
            defer { try? fm.removeItem(at: crossTarget) }
            try Data("cross-volume result".utf8).write(to: crossSource)
            precondition(try! Core.fileStamp(crossSource)?.device != Core.fileStamp(crossTarget.deletingLastPathComponent())?.device)
            try Core.OutputTarget(crossTarget).commit(crossSource)
            precondition(try! Data(contentsOf: crossTarget) == Data("cross-volume result".utf8))
            precondition(!fm.fileExists(atPath: crossSource.path))
            precondition((try! fm.attributesOfItem(atPath: crossTarget.path)[.posixPermissions] as! NSNumber).intValue == 0o600)
            print("PASS: real cross-volume Save As preserves contents and private permissions")
        }

        let importSource = root.appendingPathComponent("public-import")
        try fm.createDirectory(at: importSource, withIntermediateDirectories: true)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: importSource.path)
        let importFile = importSource.appendingPathComponent("model.bin")
        try validModel(importFile)
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: importFile.path)
        precondition(try! Core.modelFiles(importSource, requirePrivatePermissions: false).count == 1)
        do { _ = try Core.modelFiles(importSource); preconditionFailure("managed models must still be private") } catch {}
        let importStage = try WorkStage.create(beside: root.appendingPathComponent("import.ipa"), root: root.appendingPathComponent("import-stage-jobs"))
        for source in try Core.modelFiles(importSource, requirePrivatePermissions: false) {
            let copy = importStage.directory.appendingPathComponent(source.lastPathComponent)
            try fm.copyItem(at: source, to: copy)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: copy.path)
        }
        precondition(try! Core.modelFiles(importStage.directory).count == 1)
        try importStage.cleanup()
        precondition((try! fm.attributesOfItem(atPath: importFile.path)[.posixPermissions] as! NSNumber).intValue == 0o644)
        print("PASS: readable 644 import source accepted; managed copy stays private; source unchanged")

        runner.append("{\"message\":\"正在与 Apple 建立认证连接\"}\n")
        precondition(runner.title == "正在与 Apple 建立认证连接")
        runner.append("Apple could not confirm sign-in. If you received a code, enter it or leave blank: ")
        precondition(runner.title == "等待确认登录")
        precondition(InputPrompt.match(runner.currentLine) == .verificationChoice)
        runner.append("\n")
        runner.append("enter 2FA code: ")
        precondition(runner.title == "等待输入双重认证验证码")
        runner.append("\n100%\n")
        precondition(runner.progress == 1)
        runner.append("\rdownloading 100% || (100/100 B) {\"message\":\"正在整理 IPA 与应用许可\",\"phase\":\"stage\"}\n")
        precondition(runner.progress == nil && runner.title == "正在整理 IPA 与应用许可")
        runner.append("{\"message\":\"正在解密并校验可执行镜像\",\"phase\":\"images\",\"completed\":2,\"total\":4}\n")
        precondition(runner.progress == 0.5)
        print("PASS: stage progress clears stale download percentage; image progress and auth prompts update correctly")

        let checker = URL(fileURLWithPath: ProcessInfo.processInfo.environment["DESK_MODELCHECK"]!)
        let cachedStore = Store(root: root.appendingPathComponent("cache-test"), modelTool: checker)
        _ = cachedStore.add("Synthetic model cache")!
        await waitUntil { cachedStore.modelMessage != "正在校验模型…" }
        let cachedModel = cachedStore.profileURL!.appendingPathComponent("same.bin")
        try validModel(cachedModel)
        cachedStore.refreshModel(force: true)
        await waitUntil { cachedStore.modelMessage != "正在校验模型…" }
        precondition(cachedStore.modelReady)
        cachedStore.refreshModel()
        precondition(cachedStore.modelReady) // unchanged metadata reuses the cached result immediately
        try Data("broken".utf8).write(to: cachedModel)
        cachedStore.refreshModel()
        precondition(!cachedStore.modelReady)
        await waitUntil { cachedStore.modelMessage != "正在校验模型…" }
        precondition(!cachedStore.modelReady)
        let importDirectory = root.appendingPathComponent("import-model")
        try Core.privateDirectory(importDirectory)
        let importedModel = importDirectory.appendingPathComponent("same.bin")
        try validModel(importedModel)
        try cachedStore.copyValidatedModels(importDirectory, to: cachedStore.profileURL!)
        await waitUntil { cachedStore.modelMessage != "正在校验模型…" }
        precondition(cachedStore.modelReady && (try! Data(contentsOf: cachedModel)) == (try! Data(contentsOf: importedModel)))
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: cachedModel.path)
        cachedStore.refreshModel()
        precondition(!cachedStore.modelReady)
        await waitUntil { cachedStore.modelMessage != "正在校验模型…" }
        precondition(!cachedStore.modelReady)
        print("PASS: unchanged model cache reuse, content/permission invalidation, same-name damaged model repair")

        let delayedChecker = root.appendingPathComponent("delayed-modelcheck")
        let startedCheck = root.appendingPathComponent("background-check-started")
        let releaseCheck = root.appendingPathComponent("background-check-release")
        func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let checkerScript = """
        #!/bin/zsh
        if [[ ! -e \(shellQuote(startedCheck.path)) ]]; then
          /usr/bin/touch \(shellQuote(startedCheck.path))
          while [[ ! -e \(shellQuote(releaseCheck.path)) ]]; do /bin/sleep 0.02; done
        fi
        exec \(shellQuote(checker.path)) "$@"
        """
        try checkerScript.write(to: delayedChecker, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: delayedChecker.path)
        let backgroundStore = Store(root: root.appendingPathComponent("background-models"), modelTool: delayedChecker)
        let foregroundProfile = backgroundStore.add("Foreground")!
        await waitUntil { backgroundStore.modelCheckStates[foregroundProfile.id] == .invalid }
        let backgroundProfile = backgroundStore.add("Background")!
        await waitUntil { backgroundStore.modelCheckStates[backgroundProfile.id] == .invalid }
        backgroundStore.selected = foregroundProfile.id
        let backgroundModel = backgroundStore.root.appendingPathComponent("Models/\(backgroundProfile.id.uuidString)/synthetic.bin")
        try validModel(backgroundModel)
        backgroundStore.refreshModel(accountID: backgroundProfile.id)
        await waitUntil("background checker did not start") { fm.fileExists(atPath: startedCheck.path) }
        try fm.setAttributes([.modificationDate: Date().addingTimeInterval(10)], ofItemAtPath: backgroundModel.path)
        try Data().write(to: releaseCheck)
        await waitUntil("changed background model was not rechecked") { backgroundStore.modelCheckStates[backgroundProfile.id] == .valid }
        precondition(backgroundStore.selected == foregroundProfile.id && !backgroundStore.modelReady)
        try fm.removeItem(at: startedCheck)
        try fm.removeItem(at: releaseCheck)
        backgroundStore.refreshModel(accountID: backgroundProfile.id, force: true)
        await waitUntil("background version checker did not start") { fm.fileExists(atPath: startedCheck.path) }
        backgroundStore.refreshModel(accountID: backgroundProfile.id, force: true)
        try Data().write(to: releaseCheck)
        await waitUntil("invalidated background model was not rechecked") { backgroundStore.modelCheckStates[backgroundProfile.id] == .valid }
        precondition(backgroundStore.selected == foregroundProfile.id && !backgroundStore.modelReady)
        try fm.removeItem(at: startedCheck)
        try fm.removeItem(at: releaseCheck)
        backgroundStore.refreshModel(accountID: backgroundProfile.id, force: true)
        try backgroundStore.markDeleting(backgroundProfile.id)
        await waitUntil("deleted profile check did not finish") { !backgroundStore.checks.contains(backgroundProfile.id) }
        precondition(!fm.fileExists(atPath: startedCheck.path))
        precondition(backgroundStore.modelSelectors[backgroundProfile.id] == nil && backgroundStore.modelCheckStates[backgroundProfile.id] == nil)
        precondition(backgroundStore.selected == foregroundProfile.id)
        print("PASS: incomplete license, pending/legacy model hints, saved metadata reuse and non-selected model recheck")

        let danglingRoot = root.appendingPathComponent("dangling-registry")
        try Core.privateDirectory(danglingRoot)
        let danglingRegistry = danglingRoot.appendingPathComponent("profiles.json")
        try fm.createSymbolicLink(at: danglingRegistry, withDestinationURL: danglingRoot.appendingPathComponent("missing.json"))
        let danglingStore = Store(root: danglingRoot, modelTool: checker)
        precondition(!danglingStore.storageReady && danglingStore.add("Overwrite") == nil)
        precondition(try! Core.fileStamp(danglingRegistry) != nil)
        let danglingID = UUID()
        let danglingModel = danglingRoot.appendingPathComponent("Models/\(danglingID.uuidString)")
        try Core.privateDirectory(danglingModel.deletingLastPathComponent())
        try fm.createSymbolicLink(at: danglingModel, withDestinationURL: danglingRoot.appendingPathComponent("missing-model"))
        do { try Core.removeAccountData(danglingID, root: danglingRoot); preconditionFailure("must report dangling model entry") } catch {}
        precondition(try! Core.fileStamp(danglingModel) != nil)
        print("PASS: dangling registry preserved and dangling account directory cleanup reports failure")

        let id = UUID(), otherID = UUID()
        let modelDir = root.appendingPathComponent("Models/\(id.uuidString)")
        let otherModels = root.appendingPathComponent("Models/\(otherID.uuidString)")
        let session = root.appendingPathComponent("Sessions/\(id.uuidString.lowercased())")
        let otherSession = root.appendingPathComponent("Sessions/\(otherID.uuidString.lowercased())")
        let reports = root.appendingPathComponent("Reports")
        for dir in [modelDir, otherModels, session, otherSession, reports] { try Core.privateDirectory(dir) }
        try model(modelDir.appendingPathComponent("model.bin")); try model(otherModels.appendingPathComponent("other.bin"), seed: 1)
        let digest = try Core.modelHashes(in: modelDir).first!
        let legacy = reports.appendingPathComponent("old.json")
        try Core.writeJSON(["oracle": ["model_sha256": digest], "output": ["path": "temporary"]], to: legacy)
        let otherReport = reports.appendingPathComponent("other.json")
        try Core.writeJSON(["account_profile_id": otherID.uuidString], to: otherReport)
        let recycled = root.appendingPathComponent("recycled")
        try Core.recycleModels(in: modelDir, recycle: { try fm.moveItem(at: $0, to: recycled) })
        let migrated = reports.appendingPathComponent("\(id.uuidString)/old.json")
        precondition(fm.fileExists(atPath: migrated.path) && !fm.fileExists(atPath: legacy.path))
        try Core.finalizeReport(migrated, output: output, accountID: id)
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: migrated)) as! [String: Any]
        precondition((json["output"] as! [String: Any])["path"] as? String == output.path)
        precondition(json["account_profile_id"] as? String == id.uuidString)
        try Core.removeAccountData(id, root: root)
        precondition(!fm.fileExists(atPath: migrated.path) && !fm.fileExists(atPath: session.path))
        precondition(fm.fileExists(atPath: otherSession.path) && fm.fileExists(atPath: otherReport.path) && Core.hasModel(otherModels))
        try Core.removeAccountData(id, root: root)
        let bad = root.appendingPathComponent("bad-models"); try Core.privateDirectory(bad)
        try Data("invalid".utf8).write(to: bad.appendingPathComponent("bad.bin"))
        precondition(!Core.hasModel(bad))
        let unsafe = root.appendingPathComponent("linked-models"); try fm.createSymbolicLink(at: unsafe, withDestinationURL: otherModels)
        do { _ = try Core.recycleModels(in: unsafe, recycle: { _ in preconditionFailure() }); preconditionFailure() } catch {}
        print("PASS: legacy report ownership survives model deletion; complete account cleanup preserves other accounts; report final path; invalid-model and symlink rejection")

        let registryRoot = root.appendingPathComponent("registry-protected"); try Core.privateDirectory(registryRoot)
        let registry = registryRoot.appendingPathComponent("profiles.json")
        let original = try JSONEncoder().encode([Profile(id: UUID(), name: "Existing")]); try original.write(to: registry)
        try fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: registry.path)
        let blocked = Store(root: registryRoot, modelTool: URL(fileURLWithPath: "/nonexistent"))
        precondition(!blocked.storageReady && blocked.add("New") == nil)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: registry.path)
        precondition(try! Data(contentsOf: registry) == original)
        let malformedRoot = root.appendingPathComponent("malformed"); try Core.privateDirectory(malformedRoot)
        try Data("broken".utf8).write(to: malformedRoot.appendingPathComponent("profiles.json"))
        let malformed = Store(root: malformedRoot)
        precondition(!malformed.storageReady && malformed.add("New") == nil)
        let goodRoot = root.appendingPathComponent("registry-good")
        let store = Store(root: goodRoot, modelTool: URL(fileURLWithPath: "/nonexistent"))
        let a = store.add("JP")!, b = store.add("US")!
        let pending = store.add("Pending", requestedAppleID: " Pending@Example.com ")!
        precondition(store.profile(for: "pending@example.com")?.id == pending.id)
        precondition(store.profile(for: " PENDING@EXAMPLE.COM ")?.id == pending.id)
        precondition(store.profiles.first(where: { $0.id == pending.id })?.appleID == nil)
        let diskProfiles = try JSONDecoder().decode([Profile].self, from: Data(contentsOf: goodRoot.appendingPathComponent("profiles.json")))
        precondition(diskProfiles.first(where: { $0.id == pending.id })?.requestedAppleID == "pending@example.com")
        try store.bindIdentity(pending.id, email: "actual@example.com")
        precondition(store.profile(for: "actual@example.com")?.id == pending.id)
        precondition(store.profiles.first(where: { $0.id == pending.id })?.requestedAppleID == nil)
        try store.remove(pending)
        store.selected = b.id
        print("PASS: failed-login identity hint persists without binding, lookup reuses profile, verified identity replaces hint")
        try store.bindIdentity(a.id, email: "Japan@Example.com", storeFront: "143462-1,32")
        precondition(store.profiles.first(where: { $0.id == a.id })?.storeFront == "143462-1,32")
        try store.markLoginCleared(a.id)
        precondition(store.profiles.first(where: { $0.id == a.id })?.loginCleared == true)
        precondition(store.profiles.first(where: { $0.id == a.id })?.storeFront == nil)
        precondition(store.profiles.first(where: { $0.id == a.id })?.appleID == "japan@example.com")
        try store.bindIdentity(a.id, email: "Japan@Example.com", storeFront: "143465")
        precondition(store.profiles.first(where: { $0.id == a.id })?.loginCleared == false)
        let regionProfiles = try JSONDecoder().decode([Profile].self, from: Data(contentsOf: goodRoot.appendingPathComponent("profiles.json")))
        precondition(regionProfiles.first(where: { $0.id == a.id })?.storeFront == "143465")
        print("PASS: account storefront mapping, default US, persistent session region, logout clears region without unbinding identity, iOSDump schema")
        do { try store.bindIdentity(a.id, email: "different@example.com"); preconditionFailure("must reject wrong ID") } catch {}
        do { try store.bindIdentity(b.id, email: "japan@example.com"); preconditionFailure("must reject duplicate ID") } catch {}
        let unrefreshed = try store.bindRefreshedSession(b.id, in: #"{"level":"error","error":"license is required"}"#)
        precondition(!unrefreshed)
        do {
            _ = try store.bindRefreshedSession(b.id, in: #"{"sessionRefreshed":true,"email":" Japan@Example.com ","storeFront":"143462"}"# + "\n" + #"{"level":"error","error":"license is required"}"#)
            preconditionFailure("must reject refreshed duplicate ID")
        } catch {
            precondition(error.localizedDescription.contains("已绑定其他档案"))
        }
        precondition(store.profiles.first(where: { $0.id == b.id })?.appleID == nil && store.profiles.first(where: { $0.id == b.id })?.storeFront == nil)
        do {
            _ = try store.bindRefreshedSession(a.id, in: #"{"sessionRefreshed":true,"email":"different@example.com","storeFront":"143441"}"# + "\n" + #"{"level":"error","error":"license is required"}"#)
            preconditionFailure("must reject refreshed mismatched ID")
        } catch {
            precondition(error.localizedDescription.contains("不一致"))
        }
        precondition(store.profiles.first(where: { $0.id == a.id })?.appleID == "japan@example.com" && store.profiles.first(where: { $0.id == a.id })?.storeFront == "143465")
        let refreshedA = try store.bindRefreshedSession(a.id, in: #"{"sessionRefreshed":true,"email":" Japan@Example.com ","storeFront":"143462-1,32"}"# + "\n" + #"{"level":"error","error":"license is required"}"#)
        precondition(refreshedA)
        precondition(store.profiles.first(where: { $0.id == a.id })?.storeFront == "143462-1,32")
        let refreshedNoStoreFront = try store.bindRefreshedSession(a.id, in: #"{"sessionRefreshed":true,"email":"japan@example.com"}"#)
        precondition(refreshedNoStoreFront)
        precondition(store.profiles.first(where: { $0.id == a.id })?.storeFront == "143462-1,32")
        try store.markDeleting(a.id)
        precondition(store.profiles.first(where: { $0.id == a.id })?.deletionPending == true)
        try store.remove(a)
        precondition(store.profiles.count == 1 && store.selected == b.id)
        let refreshedB = try store.bindRefreshedSession(b.id, in: #"{"sessionRefreshed":true,"email":" US@Example.com ","storeFront":"143441-1,29"}"#)
        precondition(refreshedB)
        precondition(store.profiles.first(where: { $0.id == b.id })?.appleID == "us@example.com" && store.profiles.first(where: { $0.id == b.id })?.storeFront == "143441-1,29")
        let second = Store(root: goodRoot)
        precondition(!second.storageReady)
        let external = Data("external update".utf8)
        try external.write(to: goodRoot.appendingPathComponent("profiles.json"))
        do {
            _ = try store.bindRefreshedSession(b.id, in: #"{"sessionRefreshed":true,"email":"us@example.com","storeFront":"143462"}"#)
            preconditionFailure("must reject refreshed session save after external registry change")
        } catch {}
        precondition(store.profiles.first(where: { $0.id == b.id })?.storeFront == "143441-1,29")
        precondition(store.add("Overwrite") == nil)
        precondition(try! Data(contentsOf: goodRoot.appendingPathComponent("profiles.json")) == external)
        print("PASS: unreadable/corrupt registry write protection, optimistic update check, instance lock, bound account identity, duplicate prevention, pending-delete state and last-account selection")

        let jobRoot = root.appendingPathComponent("jobs"); try Core.privateDirectory(jobRoot)
        let stage = try WorkStage.create(beside: root.appendingPathComponent("artifact.ipa"), root: jobRoot)
        try Data("sensitive-temp".utf8).write(to: stage.ipa)
        try Core.writeJSON(["id": stage.id.uuidString, "path": stage.directory.path, "pid": Int32(99999999)], to: stage.registry)
        try WorkStage.recover(root: jobRoot)
        precondition(!fm.fileExists(atPath: stage.directory.path) && !fm.fileExists(atPath: stage.registry.path))
        let owner = UUID(), unrelated = UUID()
        let ownedStage = try WorkStage.create(beside: root.appendingPathComponent("owned.ipa"), root: jobRoot, accountID: owner)
        let unrelatedStage = try WorkStage.create(beside: root.appendingPathComponent("other.ipa"), root: jobRoot, accountID: unrelated)
        try Data("temporary-output".utf8).write(to: ownedStage.ipa)
        try Core.removeAccountData(owner, root: jobRoot)
        precondition(!fm.fileExists(atPath: ownedStage.directory.path) && !fm.fileExists(atPath: ownedStage.registry.path))
        precondition(fm.fileExists(atPath: unrelatedStage.directory.path))
        try unrelatedStage.cleanup()
        let brokenJobs = root.appendingPathComponent("broken-jobs"); try Core.privateDirectory(brokenJobs)
        try Data("not a directory".utf8).write(to: brokenJobs.appendingPathComponent("Jobs"))
        let beforeDirs = Set(try fm.contentsOfDirectory(atPath: root.path))
        do { _ = try WorkStage.create(beside: root.appendingPathComponent("failure.ipa"), root: brokenJobs); preconditionFailure("must reject broken registry") } catch {}
        precondition(Set(try! fm.contentsOfDirectory(atPath: root.path)) == beforeDirs)
        let explicitRoot = root.appendingPathComponent("explicit-only")
        try Core.privateDirectory(explicitRoot.appendingPathComponent("Reports"))
        let explicitReport = explicitRoot.appendingPathComponent("Reports/legacy.json")
        try Core.writeJSON(["account_profile_id": owner.uuidString], to: explicitReport)
        try Core.removeAccountData(owner, root: explicitRoot)
        precondition(!fm.fileExists(atPath: explicitReport.path))
        precondition(Core.errorHint("license is required").contains("无需清除登录"))
        precondition(Core.errorHint("free app license rejected after sign-in refresh").contains("获取"))
        precondition(Core.errorHint("generate Store AMD proof: store AMD state is not provisioned").contains("商店设备认证信息"))
        precondition(Core.errorHint("AppleMediaServices returned no Store AMD proof (<nil>)").contains("商店设备认证信息"))
        precondition(Core.errorHint("version metadata account does not match selected profile").contains("所选账户不一致"))
        precondition(Core.errorHint("failed to refresh Apple login: password is required to sign in").contains("登录会话已过期"))
        precondition(Core.errorHint("load cookie jar: unexpected end of JSON input").contains("Cookie"))
        precondition(Core.email(in: "{\"success\":true,\"email\":\"A@Example.com\"}") == "a@example.com")
        print("PASS: abandoned staging recovery, account email parsing and actionable Chinese error hints")

        // TaskDiagnostic redaction & whitelist regression coverage
        var diag = TaskDiagnostic(title: "合成诊断测试", tool: "unfairplay")
        diag.stage("准备环境")
        diag.finish("失败", exitStatus: 1)
        let multiLineAndEscaped = """
        {"level":"error","message":"Get \\"https://bag.itunes.apple.com/bag.xml?secret=abc\\": open \\"/Users/alice_secret/Downloads/App.ipa\\": failed, token=\\"bearer secret\\", email=alice_secret@example.com, phone=+8613812345678","unlisted_field":"MUST_NOT_APPEAR_SINGLE"}
        raw escaped slash: {"not_valid_tail": \\/Users\\/bob_secret\\/file and https:\\/\\/evil.example\\/leak?x=1\\" end
        {
          "PlaintextVerified": true,
          "OutputPath": "/Users/charlie_secret/App.decrypted.ipa",
          "LogicalKeySHA256": "SECRET_LOGICAL_KEY_HASH",
          "LogicalKeySHA256BySINF": {
            "Payload/App.app/SC_Info/App.sinf": "SECRET_SINF_HASH"
          },
          "success": true
        }
        [
          {
            "path": "/Users/dave_secret/App.ipa",
            "icon": "BASE64_ICON_LEAK",
            "selector_ids": ["00000001:00000002"]
          }
        ]
        """
        let quotedSecret = #"my"complex\secret/val"#
        let renderedDiag = diag.report(
            detail: "操作错误：\(NSHomeDirectory())/Downloads password=\"inline-pass\" custom=\(quotedSecret)",
            output: multiLineAndEscaped + "\n{\"message\":\"echo my\\\"complex\\\\secret/val\"}",
            secrets: [quotedSecret]
        )
        for forbidden in [
            "MUST_NOT_APPEAR_SINGLE", "SECRET_LOGICAL_KEY_HASH", "SECRET_SINF_HASH",
            "BASE64_ICON_LEAK", "LogicalKeySHA256", "OutputPath", "selector_ids",
            "alice_secret", "bob_secret", "charlie_secret", "dave_secret",
            "bag.itunes.apple.com", "evil.example", "bearer secret", "inline-pass",
            "13812345678", quotedSecret, #"my\"complex\\secret/val"#
        ] {
            precondition(!renderedDiag.contains(forbidden), "TaskDiagnostic leaked \(forbidden)")
        }
        precondition(renderedDiag.contains(#"\"[URL]\""#) && renderedDiag.contains(#"\"/Users/[用户]/Downloads/App.ipa\""#))
        precondition(renderedDiag.contains(#"{"success":true}"#) && renderedDiag.contains("~/Downloads"))

        // 24,000-char boundary must not split JSON and bypass allowedFields
        let boundaryJSON = #"{"message":"boundary-kept","forbidden_24k":"LEAK_ACROSS_24K_BOUNDARY","padding":""# + String(repeating: "p", count: 4000) + #"}"#
        let fillerLines = Array(repeating: "plain filler line 12345", count: 950).joined(separator: "\n")
        let boundaryReport = diag.report(detail: "边界测试", output: boundaryJSON + "\n" + fillerLines, secrets: [])
        precondition(!boundaryReport.contains("LEAK_ACROSS_24K_BOUNDARY") && !boundaryReport.contains("forbidden_24k"))
        let recentMarker = "最近输出（最多 24,000 字符）\n"
        if let markerRange = boundaryReport.range(of: recentMarker) {
            let recentSection = boundaryReport[markerRange.upperBound...].dropLast()
            precondition(recentSection.count <= 24_000)
        } else {
            preconditionFailure("missing recent output header")
        }

        // Head-truncated JSON (e.g. pre-sliced buffer) and EOF-unclosed multi-line JSON
        let preTruncatedSingle = #"chopped_prefix","secret_head":"HEAD_SINGLE_LEAK","message":"head-ok"}"# + "\nplain-after"
        let preTruncatedReport = diag.report(detail: "截断测试", output: preTruncatedSingle, secrets: [])
        precondition(!preTruncatedReport.contains("HEAD_SINGLE_LEAK") && !preTruncatedReport.contains("chopped_prefix"))
        precondition(preTruncatedReport.contains(#"{"message":"head-ok"}"#) && preTruncatedReport.contains("plain-after"))

        let unclosedEOF = "{\n  \"LogicalKeySHA256\": \"UNCLOSED_EOF_LEAK\",\n  \"message\": \"eof-kept\""
        let unclosedReport = diag.report(detail: "未闭合JSON", output: unclosedEOF, secrets: [])
        precondition(!unclosedReport.contains("UNCLOSED_EOF_LEAK") && unclosedReport.contains(#"{"message":"eof-kept"}"#))
        let concatAndOrphan = #"{"secret1":"CONCAT_LEAK_1"}{"message":"concat-kept","secret2":"CONCAT_LEAK_2"}"# + "\n  \"orphan_secret\": \"ORPHAN_PROP_LEAK\","
        let concatReport = diag.report(detail: "拼接JSON", output: concatAndOrphan, secrets: [])
        precondition(!concatReport.contains("CONCAT_LEAK_1") && !concatReport.contains("CONCAT_LEAK_2") && !concatReport.contains("ORPHAN_PROP_LEAK"))
        precondition(concatReport.contains(#"{"message":"concat-kept"}"#))

        // Adversarial JSON edge cases: nested head-truncated JSON, inline + broken trailing JSON, interrupted JSON, and Go \u00XX escapes
        let nestedHeadTrunc = #"chopped_prefix","message":"head-nested-kept","nested":{"a":1},"secret_tail":"TAIL_SECRET_LEAK_BYPASS"}"#
        let inlineBrokenTail = #"{"message":"step1","secretA":"LEAK_INLINE_A"}{"secretB":"LEAK_INLINE_B","message":"step2""#
        let singleUnclosedMid = #"{"LogicalKeySHA256":"LEAK_SINGLE_UNCLOSED","message":"starting-mid""# + "\nError: connection reset"
        let interruptedMulti = "{\n  \"LogicalKeySHA256\": \"LEAK_MULTI_INTERRUPTED\",\n  \"elem_secret_val\",\n  \"message\": \"interrupted-ok\"\nworker: child killed"
        let prefixedInline = #"2026-11-25 helper failed: {"code":500,"secret_p":"LEAK_PREFIX_JSON","message":"prefixed-msg"}"#
        let goUnicodeEscaped = #"request failed: "https://itunes.apple.com/buy?guid=111\u0026secret_query=SUPER_SECRET_QUERY" secret=my\u0026pass\u003c1\u003e"#
        let adversarialInput = [nestedHeadTrunc, inlineBrokenTail, singleUnclosedMid, interruptedMulti, prefixedInline, goUnicodeEscaped].joined(separator: "\n")
        let adversarialReport = diag.report(detail: "对抗测试", output: adversarialInput, secrets: ["my&pass<1>"])
        for leaked in [
            "TAIL_SECRET_LEAK_BYPASS", "secret_tail", "LEAK_INLINE_A", "LEAK_INLINE_B",
            "LEAK_SINGLE_UNCLOSED", "LEAK_MULTI_INTERRUPTED", "elem_secret_val",
            "LEAK_PREFIX_JSON", "SUPER_SECRET_QUERY", "my&pass<1>", #"my\u0026pass"#
        ] {
            precondition(!adversarialReport.contains(leaked), "Adversarial TaskDiagnostic leaked \(leaked)")
        }
        for preserved in [
            "head-nested-kept", "step1", "step2", "starting-mid", "Error: connection reset",
            "interrupted-ok", "worker: child killed", "2026-11-25 helper failed:", "prefixed-msg"
        ] {
            precondition(adversarialReport.contains(preserved), "Adversarial TaskDiagnostic lost \(preserved)")
        }
        print("PASS: TaskDiagnostic slash/quote redaction, multi-line & 24K-boundary JSON whitelist enforcement")

        if let ipatoolPath = ProcessInfo.processInfo.environment["DESK_IPATOOL"] {
            let isolatedHome = root.appendingPathComponent("corrupt-revoke-home")
            let revokeAccountID = UUID()
            let revokeSessionDir = isolatedHome.appendingPathComponent("Library/Application Support/UnfairPlayDesk/Sessions/\(revokeAccountID.uuidString.lowercased())")
            try Core.privateDirectory(revokeSessionDir)
            let corruptCookies = revokeSessionDir.appendingPathComponent("cookies")
            let corruptSession = revokeSessionDir.appendingPathComponent("session-v1.enc")
            let corruptGoCookies = isolatedHome.appendingPathComponent("corrupt-go-cookies")
            try Data("{{{corrupt-cookies".utf8).write(to: corruptCookies)
            try Data("corrupt-session-bytes".utf8).write(to: corruptSession)
            try Data("{{{corrupt-default-gocookies".utf8).write(to: corruptGoCookies)
            let previousHome = getenv("HOME").map { String(cString: $0) }
            let previousGoCookies = getenv("GOCOOKIES").map { String(cString: $0) }
            setenv("HOME", isolatedHome.path, 1)
            setenv("GOCOOKIES", corruptGoCookies.path, 1)
            defer {
                if let previousHome { setenv("HOME", previousHome, 1) } else { unsetenv("HOME") }
                if let previousGoCookies { setenv("GOCOOKIES", previousGoCookies, 1) } else { unsetenv("GOCOOKIES") }
            }
            let revokeRunner = Runner(verify: {})
            let revokeOK = await withCheckedContinuation { continuation in
                revokeRunner.launch(
                    URL(fileURLWithPath: ipatoolPath),
                    ["--profile", revokeAccountID.uuidString, "--format", "json", "auth", "revoke"],
                    title: "清除损坏会话",
                    sessionAccount: revokeAccountID,
                    deletingSession: true
                ) { continuation.resume(returning: $0) }
            }
            precondition(revokeOK, "ipatool auth revoke failed under corrupt cookies: \(revokeRunner.output)")
            precondition(!fm.fileExists(atPath: corruptCookies.path) && !fm.fileExists(atPath: corruptSession.path))
            print("PASS: end-to-end ipatool auth revoke succeeds and cleans up corrupt cookies and corrupt encrypted session")
        }

        // Diagnostic preservation across post-failure cleanup and partial-failure batches
        let diagRunner = Runner(verify: {})
        let failedModelCheck = await withCheckedContinuation { continuation in
            diagRunner.launch(URL(fileURLWithPath: "/bin/zsh"), ["-c", "printf 'error: synthetic modelcheck failure\\n'; exit 3"], title: "正在校验待导入模型", holdsCompletion: true) {
                continuation.resume(returning: $0)
            }
        }
        precondition(!failedModelCheck && diagRunner.busy)
        let cleanupOutcome = await diagRunner.fileWork("正在清理临时文件…", preserveFailure: true) { () }
        guard case .success = cleanupOutcome else { preconditionFailure("cleanup failed") }
        diagRunner.finishCompletion()
        let preservedModelDiag = diagRunner.diagnosticReport(detail: "导入失败")
        precondition(preservedModelDiag.contains("结果  失败") && preservedModelDiag.contains("退出码  3") && preservedModelDiag.contains("synthetic modelcheck failure"))

        // Pre-launch batch staging failure diagnostic context
        let stageBatchRunner = Runner(verify: {})
        let stageBatchToken = stageBatchRunner.beginBatch("正在解密 IPA")!
        stageBatchRunner.recordStage("正在准备 broken.ipa")
        stageBatchRunner.recordBatchFailure("处理 broken.ipa 失败", detail: "synthetic staging permission error")
        stageBatchRunner.finishBatch(stageBatchToken)
        let stageFailReport = stageBatchRunner.diagnosticReport(detail: "暂存失败")
        precondition(stageFailReport.contains("结果  失败") && !stageFailReport.contains("结果  应用提示") && stageFailReport.contains("synthetic staging permission error"))

        // Recovered Save As retry inside single-file batch must not poison final batch result,
        // and post-tool recordBatchFailure must preserve prior tool output & stages
        let saveRetryRunner = Runner(verify: {})
        let saveRetryToken = saveRetryRunner.beginBatch("正在解密 IPA")!
        let decryptOK = await withCheckedContinuation { continuation in
            saveRetryRunner.launch(URL(fileURLWithPath: "/bin/zsh"), ["-c", "printf 'decrypt engine ok\\n'; exit 0"], title: "正在解密 retry.ipa", holdsCompletion: true, batchID: saveRetryToken) {
                continuation.resume(returning: $0)
            }
        }
        precondition(decryptOK)
        let firstSaveAttempt = await saveRetryRunner.saveFile { throw DeskError("transient save target busy") }
        if case .success = firstSaveAttempt { preconditionFailure("expected first save to fail") }
        let secondSaveAttempt = await saveRetryRunner.saveFile { () }
        guard case .success = secondSaveAttempt else { preconditionFailure("expected retry save to succeed") }
        saveRetryRunner.finishCompletion()
        saveRetryRunner.finishBatch(saveRetryToken)
        let retryDiagReport = saveRetryRunner.diagnosticReport(detail: "重试保存完成")
        precondition(retryDiagReport.contains("结果  成功") && saveRetryRunner.title != "操作失败")

        let postToolFailRunner = Runner(verify: {})
        let postToolToken = postToolFailRunner.beginBatch("正在解密 IPA")!
        let toolSucceeded = await withCheckedContinuation { continuation in
            postToolFailRunner.launch(URL(fileURLWithPath: "/bin/zsh"), ["-c", "printf 'engine stdout context\\n'; exit 0"], title: "正在解密 postfail.ipa", holdsCompletion: true, batchID: postToolToken) {
                continuation.resume(returning: $0)
            }
        }
        precondition(toolSucceeded)
        postToolFailRunner.recordBatchFailure("写入 postfail.ipa 解密报告失败", detail: "report disk full")
        postToolFailRunner.finishCompletion()
        postToolFailRunner.finishBatch(postToolToken)
        let postToolDiag = postToolFailRunner.diagnosticReport(detail: "报告写入失败")
        precondition(postToolDiag.contains("结果  失败") && postToolDiag.contains("engine stdout context") && postToolDiag.contains("report disk full") && postToolDiag.contains("写入 postfail.ipa 解密报告失败"))

        // Partial batch failure must not be overwritten by subsequent successful item
        let partialRunner = Runner(verify: {})
        let partialToken = partialRunner.beginBatch("正在解密 IPA")!
        let item1 = await withCheckedContinuation { continuation in
            partialRunner.launch(URL(fileURLWithPath: "/bin/zsh"), ["-c", "printf 'error: first ipa failed\\n'; exit 5"], title: "正在解密 first.ipa", holdsCompletion: true, batchID: partialToken) {
                continuation.resume(returning: $0)
            }
        }
        precondition(!item1)
        partialRunner.finishCompletion()
        let item2 = await withCheckedContinuation { continuation in
            partialRunner.launch(URL(fileURLWithPath: "/bin/zsh"), ["-c", "printf 'second ipa ok\\n'; exit 0"], title: "正在解密 second.ipa", holdsCompletion: true, batchID: partialToken) {
                continuation.resume(returning: $0)
            }
        }
        precondition(item2)
        partialRunner.finishCompletion()
        partialRunner.finishBatch(partialToken)
        let partialReport = partialRunner.diagnosticReport(detail: "部分失败")
        precondition(partialReport.contains("结果  失败") && partialReport.contains("退出码  5") && partialReport.contains("first ipa failed"))
        precondition(partialRunner.output.contains("first ipa failed") && partialRunner.log.contains("first ipa failed"))
        print("PASS: diagnostic result and logs preserved across cleanup, staging failure, and partial batch failure")

        // 1.5.7 -> 1.5.8 local session status before & after lazy migration (including real macOS Keychain & symlink dir check)
        let sessionStatusRoot = root.appendingPathComponent("session-status-test")
        let migratedID = UUID(), legacyKeychainID = UUID(), legacyFileID = UUID(), missingSessionID = UUID(), symlinkSessionID = UUID()
        let migratedDir = sessionStatusRoot.appendingPathComponent("Sessions/\(migratedID.uuidString.lowercased())")
        let legacyFileDir = sessionStatusRoot.appendingPathComponent("Sessions/\(legacyFileID.uuidString.lowercased())")
        let symlinkSessionDir = sessionStatusRoot.appendingPathComponent("Sessions/\(symlinkSessionID.uuidString.lowercased())")
        try Core.privateDirectory(migratedDir)
        try Core.privateDirectory(legacyFileDir)
        try Data("ciphertext".utf8).write(to: migratedDir.appendingPathComponent("session-v1.enc"))
        try Data("legacy-file-cred".utf8).write(to: legacyFileDir.appendingPathComponent("account"))
        try fm.createSymbolicLink(at: symlinkSessionDir, withDestinationURL: migratedDir)
        precondition(Core.localSessionStatus(accountID: migratedID, canDownload: true, fallbackStatus: "已登录", root: sessionStatusRoot, hasLegacyKeychainSession: { _ in false }) == "本地会话已保存")
        precondition(Core.localSessionStatus(accountID: symlinkSessionID, canDownload: true, fallbackStatus: "已登录", root: sessionStatusRoot, hasLegacyKeychainSession: { _ in false }) == "无法读取本地会话状态")
        precondition(Core.localSessionStatus(accountID: legacyKeychainID, canDownload: true, fallbackStatus: "已登录", root: sessionStatusRoot, hasLegacyKeychainSession: { $0 == legacyKeychainID }) == "旧版会话待首次使用时迁移")
        precondition(Core.localSessionStatus(accountID: legacyFileID, canDownload: true, fallbackStatus: "已登录", root: sessionStatusRoot, hasLegacyKeychainSession: { _ in false }) == "旧版会话待首次使用时迁移")
        precondition(Core.localSessionStatus(accountID: missingSessionID, canDownload: true, fallbackStatus: "已登录", root: sessionStatusRoot, hasLegacyKeychainSession: { _ in false }) == "未找到本地会话文件")
        precondition(Core.localSessionStatus(accountID: migratedID, canDownload: false, fallbackStatus: "未登录", root: sessionStatusRoot, hasLegacyKeychainSession: { _ in true }) == "未登录")

        let realLegacyKeychainID = UUID()
        let legacyKCService = "ipatool-auth.service." + realLegacyKeychainID.uuidString.lowercased()
        let legacyKCBaseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyKCService,
            kSecAttrAccount as String: "account"
        ]
        precondition(!Core.hasLegacyKeychainSession(realLegacyKeychainID))
        var legacyKCAdd = legacyKCBaseQuery
        legacyKCAdd[kSecValueData as String] = Data("synthetic-legacy-1.5.7-account".utf8)
        let addStatus = SecItemAdd(legacyKCAdd as CFDictionary, nil)
        if addStatus == errSecSuccess {
            defer { _ = SecItemDelete(legacyKCBaseQuery as CFDictionary) }
            precondition(Core.hasLegacyKeychainSession(realLegacyKeychainID))
            precondition(Core.localSessionStatus(accountID: realLegacyKeychainID, canDownload: true, fallbackStatus: "已登录", root: sessionStatusRoot) == "旧版会话待首次使用时迁移")
            _ = SecItemDelete(legacyKCBaseQuery as CFDictionary)
            precondition(!Core.hasLegacyKeychainSession(realLegacyKeychainID))
        }
        print("PASS: local session status distinguishes migrated encrypted session, pending 1.5.7 legacy session, and missing session")

        // UpdateChecker status codes, error messages, and available state reset
        var mockStatus = 200
        var mockBody = Data(#"{"tag_name":"v1.6.0","draft":false,"prerelease":false}"#.utf8)
        var mockError: Error?
        let releaseEndpoint = URL(string: "https://api.github.com/repos/Emokui/UnfairPlay/releases/latest")!
        let checkerInstance = UpdateChecker(fetch: { _ in
            if let mockError { throw mockError }
            let response = HTTPURLResponse(url: releaseEndpoint, statusCode: mockStatus, httpVersion: nil, headerFields: nil)!
            return (mockBody, response)
        }, versionProvider: { "1.5.8" })
        await checkerInstance.check()
        precondition(checkerInstance.available == "v1.6.0" && checkerInstance.message == nil)
        mockBody = Data(#"{"tag_name":"v1.6.0","draft":true,"prerelease":false}"#.utf8)
        await checkerInstance.check(manual: true)
        precondition(checkerInstance.available == nil && checkerInstance.message == nil)
        mockBody = Data(#"{"tag_name":"v1.6.1","draft":false,"prerelease":false}"#.utf8)
        await checkerInstance.check(manual: true)
        precondition(checkerInstance.available == "v1.6.1")
        mockStatus = 404
        await checkerInstance.check(manual: true)
        precondition(checkerInstance.available == nil && checkerInstance.message == "当前尚无已发布的正式版本。")
        mockStatus = 429
        await checkerInstance.check(manual: true)
        precondition(checkerInstance.message == "GitHub 更新接口请求受限，请稍后重试。")
        mockStatus = 503
        await checkerInstance.check(manual: true)
        precondition(checkerInstance.message == "暂时无法获取更新（HTTP 503），请稍后重试。")
        mockError = URLError(.notConnectedToInternet)
        await checkerInstance.check(manual: true)
        precondition(checkerInstance.message == "检查更新失败，请检查网络后重试。")
        print("PASS: UpdateChecker preserves HTTP 404/429/5xx semantics and clears stale available version on draft/prerelease/404")

        await waitUntil { Runner.active.isEmpty }
        print("ALL REGRESSION TESTS PASSED")
    }
}
