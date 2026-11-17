import SwiftUI

enum DeskAppearance {
    static let icon = Bundle.main.resourceURL.flatMap { NSImage(contentsOf: $0.appendingPathComponent("AppIcon.png")) }
    static let accent = Color(red: 0.36, green: 0.36, blue: 0.82)
    static let background = Color(red: 0.965, green: 0.968, blue: 0.982)
    static let sidebar = Color(red: 0.935, green: 0.941, blue: 0.964)
    static let surface = Color.white
    static let contentWidth: CGFloat = 780
}

struct DeskSheetHeader: View {
    let symbol: String
    let title: String
    let message: String
    var subtitle = ""

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: symbol).font(.system(size: 24, weight: .medium))
                .foregroundStyle(DeskAppearance.accent).frame(width: 48, height: 48)
                .background(DeskAppearance.accent.opacity(0.09), in: RoundedRectangle(cornerRadius: 13))
                .accessibilityHidden(true)
            Text(title).font(.system(size: 17, weight: .semibold))
            if !subtitle.isEmpty { Text(subtitle).font(.system(size: 12, weight: .medium)).lineLimit(1) }
            Text(message).font(.system(size: 12)).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }.frame(maxWidth: .infinity)
    }
}

extension View {
    func deskCard(cornerRadius: CGFloat = 16) -> some View {
        self.frame(maxWidth: .infinity, alignment: .leading)
            .background(DeskAppearance.surface, in: RoundedRectangle(cornerRadius: cornerRadius))
            .overlay(RoundedRectangle(cornerRadius: cornerRadius).strokeBorder(Color.primary.opacity(0.035), lineWidth: 1))
    }
}

struct DeskPrimaryButtonStyle: ButtonStyle {
    var compact = false
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: compact ? 11 : 12, weight: .semibold))
            .padding(.horizontal, compact ? 13 : 18).padding(.vertical, compact ? 7 : 11)
            .foregroundStyle(enabled ? Color.white : DeskAppearance.accent.opacity(0.35))
            .background(enabled ? DeskAppearance.accent.opacity(configuration.isPressed ? 0.8 : 1) : DeskAppearance.accent.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            .contentShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct DeskEmptyState: View {
    var symbol: String
    var title: String
    var message: String
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: symbol).font(.system(size: 34, weight: .ultraLight))
                .foregroundStyle(DeskAppearance.accent).frame(width: 68, height: 68)
                .background(DeskAppearance.accent.opacity(0.07), in: RoundedRectangle(cornerRadius: 20))
            if !title.isEmpty { Text(title).font(.system(size: 16, weight: .medium)) }
            Text(message).font(.system(size: 12)).foregroundStyle(.secondary).multilineTextAlignment(.center).lineSpacing(5)
        }.padding(30).frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// Observe outside clicks without consuming events from buttons or text fields.
struct OutsideClickMonitor: NSViewRepresentable {
    var dismiss: () -> Void
    func makeNSView(context: Context) -> ClickView { ClickView(dismiss: dismiss) }
    func updateNSView(_ view: ClickView, context: Context) { view.dismiss = dismiss }
    static func dismantleNSView(_ view: ClickView, coordinator: ()) { view.stop() }

    final class ClickView: NSView {
        var dismiss: () -> Void
        private var monitor: Any?
        init(dismiss: @escaping () -> Void) {
            self.dismiss = dismiss
            super.init(frame: .zero)
            monitor = NSEvent.addLocalMonitorForEvents(matching: .leftMouseDown) { [weak self] event in
                if let self, let window = self.window, event.window === window,
                   !self.bounds.contains(self.convert(event.locationInWindow, from: nil)) {
                    self.dismiss()
                }
                return event
            }
        }
        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
        override func hitTest(_ point: NSPoint) -> NSView? { nil }
        func stop() { if let monitor { NSEvent.removeMonitor(monitor) }; monitor = nil }
        deinit { stop() }
    }
}
