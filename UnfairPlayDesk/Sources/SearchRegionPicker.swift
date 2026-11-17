import SwiftUI

struct SearchRegionPicker: View {
    let country: String
    let select: (String) -> Void
    @ViewState private var expanded = false
    @ViewState private var query = ""
    @FocusState private var queryFocused: Bool

    var body: some View {
        Button {
            query = ""
            expanded.toggle()
        } label: {
            Text("地区 \(StorefrontRegions.name(for: country))")
                .font(.system(size: 11, weight: .medium)).foregroundStyle(DeskAppearance.accent)
                .lineLimit(1).frame(maxWidth: 118).fixedSize(horizontal: true, vertical: false)
                .padding(.horizontal, 8).padding(.vertical, 5)
                .background(DeskAppearance.accent.opacity(0.07), in: RoundedRectangle(cornerRadius: 6))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("切换搜索地区（\(country)）")
        .accessibilityLabel("搜索地区，\(StorefrontRegions.name(for: country))")
        .popover(isPresented: $expanded, arrowEdge: .bottom) { regionList }
    }

    private var regionList: some View {
        let input = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let regions = input.isEmpty ? StorefrontRegions.defaultOrder(current: country) : StorefrontRegions.matches(input)
        let match = !input.isEmpty && regions.count == 1 ? regions.first : nil

        return VStack(alignment: .leading, spacing: 8) {
            Group {
                if regions.isEmpty {
                    Text("没有匹配的地区").font(.caption).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 2) {
                            ForEach(regions) { region in
                                Button { choose(region.id) } label: {
                                    HStack(spacing: 8) {
                                        Text(region.name).lineLimit(1)
                                        Spacer()
                                        Text(region.id).font(.caption).foregroundStyle(.secondary)
                                        if region.id == country {
                                            Image(systemName: "checkmark")
                                                .font(.system(size: 10, weight: .semibold)).foregroundStyle(DeskAppearance.accent)
                                        }
                                    }.padding(.horizontal, 6).frame(height: 27)
                                        .contentShape(Rectangle())
                                }.buttonStyle(.plain)
                            }
                        }
                    }
                }
            }.frame(height: 240)
            Divider()
            HStack(spacing: 8) {
                TextField("地区名称或代码", text: $query)
                    .textFieldStyle(.roundedBorder).focused($queryFocused)
                    .onSubmit { if let match { choose(match.id) } }
                Button("选择") { if let match { choose(match.id) } }
                    .controlSize(.small).disabled(match == nil)
            }
        }.padding(12).frame(width: 230).onAppear { queryFocused = true }
    }

    private func choose(_ code: String) {
        select(code)
        expanded = false
    }
}
