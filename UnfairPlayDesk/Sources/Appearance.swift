import SwiftUI

enum DeskAppearance {
    static let icon = Bundle.main.resourceURL.flatMap { NSImage(contentsOf: $0.appendingPathComponent("AppIcon.png")) }
}

extension View {
    func deskCard() -> some View {
        self.frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.primary.opacity(0.06), lineWidth: 1))
    }
}

// Observe outside clicks without consuming events from buttons or text fields.
struct ConsoleDismissMonitor: NSViewRepresentable {
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
