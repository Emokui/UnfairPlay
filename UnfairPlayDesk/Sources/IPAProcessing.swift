import SwiftUI
import AppKit
import UniformTypeIdentifiers

extension ContentView {
    func addInputIPAs(_ files: [URL]) {
        var known = Set(inputIPAs)
        let newFiles = files.filter { $0.isFileURL && $0.pathExtension.lowercased() == "ipa" }
            .map(\.standardizedFileURL)
            .filter { !Core.isMissingFile($0) && known.insert($0).inserted }
        guard !newFiles.isEmpty else { return }
        inputIPAs.append(contentsOf: newFiles)
        var added = Set(manuallyAddedIPAs)
        manuallyAddedIPAs.append(contentsOf: newFiles.filter { added.insert($0).inserted })
    }

    func addIPAsFromPicker() {
        let picker = NSOpenPanel()
        picker.directoryURL = defaultDownloadFolder
        picker.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .data]
        picker.canChooseDirectories = false
        picker.allowsMultipleSelection = true
        if picker.runModal() == .OK { addInputIPAs(picker.urls) }
    }

    func trashSelectedIPAs() {
        guard !runner.busy else { return }
        refreshIPAReferences()
        let files = inputIPAs
        guard !files.isEmpty else { return }
        let confirmation = NSAlert()
        confirmation.alertStyle = .warning
        confirmation.messageText = "将选中的 \(files.count) 份 IPA 移到废纸篓？"
        if let file = files.first, files.count == 1 { confirmation.informativeText = file.lastPathComponent }
        confirmation.addButton(withTitle: "取消")
        confirmation.addButton(withTitle: "移到废纸篓")
        guard confirmation.runModal() == .alertSecondButtonReturn else { return }

        Task { @MainActor in
            let outcome = await runner.fileWork("正在将 IPA 移到废纸篓…") { Core.recycleIPAs(files) }
            switch outcome {
            case .success(let (removed, failures)):
                inputIPAs.removeAll { removed.contains($0.path) }
                recentIPAOutputs.removeAll { removed.contains($0.path) }
                let remainingDownloads = downloadedIPAs.filter { !removed.contains($0.id) }
                if remainingDownloads.count != downloadedIPAs.count {
                    downloadedIPAs = remainingDownloads
                    DownloadedIPA.save(remainingDownloads)
                }
                refreshIPAReferences()
                ipaFolderRevision += 1
                if !failures.isEmpty {
                    alertText = "\(failures.count) 份 IPA 未能移到废纸篓。\n\n" + failures.prefix(4).joined(separator: "\n")
                }
            case .failure(let error):
                alertText = error.localizedDescription
            }
        }
    }

    func processSelectedIPAs(verifyOnly: Bool) {
        guard !runner.busy, store.canUseSelected, store.modelReady,
              let model = store.profileURL, let accountID = store.selected else { return }
        refreshIPAReferences()
        let inputs = verifyOnly ? inputIPAs : decryptableIPAs
        guard let first = inputs.first else { return }
        let batch = inputs.count > 1
        let automatic = saveIPAsDirectly

        let destination: URL?
        if verifyOnly {
            destination = nil
        } else if saveIPAsDirectly {
            guard let folder = downloadDirectory() else { return }
            destination = folder
        } else if batch {
            let picker = NSOpenPanel()
            picker.directoryURL = defaultDownloadFolder
            picker.canChooseDirectories = true
            picker.canChooseFiles = false
            picker.canCreateDirectories = true
            picker.message = "选择批量解密后的 IPA 保存文件夹。"
            picker.prompt = "选择输出文件夹"
            guard picker.runModal() == .OK, let folder = picker.url else { return }
            destination = folder
        } else {
            let picker = NSSavePanel()
            picker.directoryURL = defaultDownloadFolder
            picker.nameFieldStringValue = first.deletingPathExtension().lastPathComponent + ".decrypted.ipa"
            picker.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .data]
            guard picker.runModal() == .OK, let file = picker.url else { return }
            if Core.sameFile(first, file) {
                alertText = "输出位置与原始 IPA 实际上是同一个文件。"
                return
            }
            destination = file
        }

        let reportFolder = store.root.appendingPathComponent("Reports/\(accountID.uuidString)")
        if destination != nil {
            do { try Core.privateDirectory(reportFolder) }
            catch { alertText = error.localizedDescription; return }
        }

        Task { @MainActor in
            guard let batchToken = runner.beginBatch(verifyOnly ? "正在验证 IPA" : "正在解密 IPA") else { return }
            if !verifyOnly { completionNotice = nil }
            var completed = 0
            var cancelled = false
            var issues: [String] = []
            var outputs: [URL] = []
            defer { ipaBatchPosition = nil; runner.finishBatch(batchToken) }

            for (index, input) in inputs.enumerated() {
                if runner.cancelled { cancelled = true; break }
                if batch { ipaBatchPosition = "\(index + 1)/\(inputs.count)" }
                do {
                    let target = try destination.map {
                        if batch || automatic { return try unusedDecryptedTarget(for: input, in: $0) }
                        return try Core.OutputTarget($0)
                    }
                    let stage = try target.map { try WorkStage.create(beside: $0.url, root: store.root, accountID: accountID) }
                    defer {
                        if let stage {
                            do { try stage.cleanup() }
                            catch { issues.append("\(input.lastPathComponent)：临时目录清理失败。") }
                        }
                        runner.finishCompletion()
                    }

                    var arguments = [verifyOnly ? "verify" : "decrypt", "--input", input.path, "--model", model.path]
                    if let stage { arguments += ["--output", stage.ipa.path, "--report", stage.report.path] }
                    let title = verifyOnly ? "正在验证 \(input.lastPathComponent)" : "正在解密 \(input.lastPathComponent)"
                    let ok = await withCheckedContinuation { continuation in
                        runner.launch(tool("unfairplay"), arguments, title: title, holdsCompletion: true, batchID: batchToken) {
                            continuation.resume(returning: $0)
                        }
                    }
                    if runner.cancelled {
                        cancelled = true
                        break
                    }
                    guard ok else {
                        issues.append(Core.operationError(title: input.lastPathComponent, hint: runner.hint, output: runner.output))
                        continue
                    }
                    if let stage, let target {
                        let saved: URL
                        if batch {
                            let outcome = await runner.saveFile { try target.commit(stage.ipa, protecting: input) }
                            try outcome.get()
                            saved = target.url
                        } else {
                            guard let file = await saveCompletedIPA(stage.ipa, destination: target, protecting: input) else {
                                issues.append("\(input.lastPathComponent)：结果未保存。")
                                continue
                            }
                            saved = file
                        }
                        completed += 1
                        let file = saved.standardizedFileURL
                        outputs.append(file)
                        do {
                            try Core.finalizeReport(stage.report, output: saved, accountID: accountID)
                            let report = try JSONSerialization.jsonObject(with: Data(contentsOf: stage.report))
                            try Core.writeJSON(report, to: reportFolder.appendingPathComponent("\(UUID().uuidString).json"))
                        } catch {
                            issues.append("\(saved.lastPathComponent)：已保存，报告写入失败。\(error.localizedDescription)")
                        }
                    } else {
                        completed += 1
                    }
                } catch {
                    issues.append("\(input.lastPathComponent)：\(error.localizedDescription)")
                }
            }

            var known = Set(recentIPAOutputs)
            recentIPAOutputs.append(contentsOf: outputs.filter { known.insert($0).inserted })
            if !verifyOnly { ipaFolderRevision += 1 }
            if cancelled || !issues.isEmpty {
                var summary = verifyOnly ? "已通过验证 \(completed)/\(inputs.count) 份 IPA。" : "已保存 \(completed)/\(inputs.count) 份 IPA。"
                if cancelled { summary += "\n批次已取消。" }
                if !issues.isEmpty {
                    summary += "\n\n" + issues.prefix(4).joined(separator: "\n\n")
                    if issues.count > 4 { summary += "\n\n另有 \(issues.count - 4) 条问题。" }
                }
                alertText = summary
            } else if verifyOnly {
                showCompletion(completed == 1 ? "IPA 验证通过" : "已验证 \(completed) 份 IPA")
            }
        }
    }

    private func unusedDecryptedTarget(for input: URL, in folder: URL) throws -> Core.OutputTarget {
        let name = input.deletingPathExtension().lastPathComponent
        var index = 1
        while true {
            let suffix = index == 1 ? "" : "-\(index)"
            let target = try Core.OutputTarget(folder.appendingPathComponent("\(name)\(suffix).decrypted.ipa"))
            if target.original == nil { return target }
            index += 1
        }
    }
}
