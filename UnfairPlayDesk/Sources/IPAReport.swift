import SwiftUI
import AppKit

struct IPAReportView: View {
    let report: IPASavedReport
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("解密报告").font(.system(size: 18, weight: .semibold))
                    Text(URL(fileURLWithPath: report.document.output.path).lastPathComponent).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    let document = report.document
                    Label(document.plaintext_verified == true ? "明文页哈希验证通过" : "校验方式见镜像详情",
                          systemImage: document.plaintext_verified == true ? "checkmark.seal" : "exclamationmark.circle")
                        .foregroundStyle(document.plaintext_verified == true ? DeskAppearance.accent : Color.secondary)
                    HStack(spacing: 24) {
                        Text("加密镜像  \(document.encrypted_image_count ?? 0)")
                        Text("解密页数  \(document.decrypted_page_count ?? 0)")
                    }.font(.system(size: 12)).monospacedDigit()
                    Text(document.complete == true ? "报告记录的处理流程完整" : "报告记录的处理流程未完成")
                    Text(document.signature_verified == true ? "签名校验通过" : "签名尚未验证").foregroundStyle(.secondary)
                    Divider()
                    Text("输入 SHA-256").font(.caption).foregroundStyle(.secondary)
                    Text(document.input.sha256 ?? "未记录").font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                    Text("输出 SHA-256").font(.caption).foregroundStyle(.secondary)
                    Text(document.output.sha256 ?? "未记录").font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                    if let images = document.images {
                        ForEach(Array(images.enumerated()), id: \.offset) { _, image in
                            DisclosureGroup {
                                VStack(alignment: .leading, spacing: 7) {
                                    if let architecture = image.architecture { Text(architecture) }
                                    Text("审核方式  " + image.auditDescription)
                                    Text("处理页数  \(image.pages ?? 0)")
                                    ForEach(Array((image.pre_encryption_code_directories ?? []).enumerated()), id: \.offset) { index, audit in
                                        Text("明文页哈希 \(index + 1)  ·  \(audit.matched_slots)/\(audit.slot_count) 个槽位匹配")
                                    }
                                    ForEach(Array((image.code_directories ?? []).enumerated()), id: \.offset) { index, audit in
                                        Text("加密源页哈希 \(index + 1)  ·  \(audit.matched_slots)/\(audit.slot_count) 个槽位匹配")
                                    }
                                }.font(.system(size: 11)).foregroundStyle(.secondary).padding(.vertical, 7).textSelection(.enabled)
                            } label: { Text(image.member).font(.system(size: 11)).lineLimit(2) }
                        }
                    }
                    ForEach(document.warnings ?? [], id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(16).deskCard()
            }
            HStack {
                Text("此处展示已保存报告中的记录。").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("在 Finder 中显示 JSON") { NSWorkspace.shared.activateFileViewerSelecting([report.url]) }
            }
        }.padding(24).frame(width: 620, height: 560).background(DeskAppearance.background)
    }
}
