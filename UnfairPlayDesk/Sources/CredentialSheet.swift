import SwiftUI

private extension InputPrompt {
    var symbol: String {
        switch self {
        case .account: "person.crop.circle"
        case .password, .passphrase: "key.horizontal"
        case .verification: "lock.shield"
        case .verificationChoice: "exclamationmark.shield"
        }
    }
    var message: String {
        switch self {
        case .account: "输入 Apple 账户的邮箱地址或手机号。"
        case .password: "输入 Apple 账户密码以继续。"
        case .verification: "输入 Apple 为本次登录提供的 6 位验证码。"
        case .verificationChoice: "请先核对 Apple 账户和密码。已收到本次登录验证码时，可以继续输入。"
        case .passphrase: "输入本地凭据库的解锁口令。它与 Apple 账户密码不同。"
        }
    }
}

struct CredentialSheet: View {
    let prompt: InputPrompt
    let account: String
    let submit: (String) -> Void
    let cancel: () -> Void
    @ViewState private var value = ""
    @ViewState private var confirmedCode = false
    @ViewState private var passwordVisible = false
    @FocusState private var focused: Bool

    private var activePrompt: InputPrompt { confirmedCode ? .verification : prompt }
    private var valid: Bool {
        activePrompt == .verification ? value.count == 6 : !value.isEmpty
    }
    private func send() {
        guard valid else { return }
        let input = value
        value = ""
        submit(input)
    }

    var body: some View {
        VStack(spacing: 12) {
            DeskSheetHeader(symbol: activePrompt.symbol, title: activePrompt.title, message: activePrompt.message, subtitle: account)
            if activePrompt != .verificationChoice { credentialField.padding(.vertical, 5) }
            HStack(spacing: 10) {
                Spacer()
                Button("取消", role: .cancel) { value = ""; cancel() }.keyboardShortcut(.cancelAction)
                if activePrompt == .verificationChoice {
                    Button("已收到验证码") { confirmedCode = true }
                        .buttonStyle(DeskPrimaryButtonStyle(compact: true))
                } else {
                    Button(activePrompt == .verification ? "验证" : "继续", action: send)
                        .buttonStyle(DeskPrimaryButtonStyle(compact: true)).keyboardShortcut(.defaultAction).disabled(!valid)
                }
            }
        }.padding(24).frame(width: 360)
    }

    private var credentialField: some View {
        HStack(spacing: 8) {
            Group {
                switch activePrompt {
                case .password:
                    if passwordVisible { TextField(activePrompt.title, text: $value).autocorrectionDisabled() }
                    else { SecureField(activePrompt.title, text: $value) }
                case .passphrase:
                    SecureField(activePrompt.title, text: $value)
                case .verification:
                    TextField("6 位验证码", text: $value).monospacedDigit()
                        .onChange(of: value) {
                            let digits = String(value.filter { "0123456789".contains($0) }.prefix(6))
                            if value != digits { value = digits }
                        }
                case .account:
                    TextField("邮箱地址或手机号", text: $value)
                case .verificationChoice:
                    EmptyView()
                }
            }.textFieldStyle(.roundedBorder).controlSize(.large).focused($focused)
                .accessibilityLabel(activePrompt.title).onSubmit(send)
                .task(id: passwordVisible) { focused = true }
            if activePrompt == .password {
                let label = passwordVisible ? "隐藏密码" : "显示密码"
                Button { passwordVisible.toggle() } label: {
                    Image(systemName: passwordVisible ? "eye.slash" : "eye")
                        .foregroundStyle(.secondary).frame(width: 26, height: 26)
                        .contentShape(Rectangle())
                }.buttonStyle(.plain).help(label).accessibilityLabel(label)
            }
        }
    }
}
