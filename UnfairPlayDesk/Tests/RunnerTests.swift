import Foundation
import Darwin

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
        let reportOutput = root.appendingPathComponent("synthetic-result.ipa")
        let reportJSON: [String: Any] = [
            "input": ["path": root.appendingPathComponent("synthetic-input.ipa").path, "sha256": "input-hash"],
            "output": ["path": reportOutput.path, "sha256": "output-hash"],
            "complete": true, "plaintext_verified": false,
            "images": [["member": "Payload/Test.app/Test", "first_page_audit": "arm64-instruction-decode"]]
        ]
        try Core.writeJSON(reportJSON, to: reportDirectory.appendingPathComponent("synthetic.json"))
        let savedReport = try IPASavedReport.find(for: reportOutput, root: reportDirectory.deletingLastPathComponent())
        precondition(savedReport.document.output.sha256 == "output-hash")
        precondition(savedReport.document.images?.first?.auditDescription == "ARM64 指令结构审计")
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
        precondition(Core.email(in: "{\"success\":true,\"email\":\"A@Example.com\"}") == "a@example.com")
        print("PASS: abandoned staging recovery, account email parsing and actionable Chinese error hints")
        await waitUntil { Runner.active.isEmpty }
        print("ALL REGRESSION TESTS PASSED")
    }
}
