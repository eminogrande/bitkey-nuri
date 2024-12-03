import Shared
import SwiftUI

// MARK: -

struct IconView: View {

    let model: Shared.IconModel
    var colorOverride: Color? = nil

    var body: some View {
        let alignment: Alignment = switch model.iconAlignmentInBackground {
        case .topstart:
            .topLeading
        case .topcenter:
            .top
        case .topend:
            .topTrailing
        case .start:
            .leading
        case .center:
            .center
        case .end:
            .trailing
        case .bottomstart:
            .bottomLeading
        case .bottomcenter:
            .bottom
        case .bottomend:
            .bottomTrailing
        default:
            .center
        }

        let t = if let badgeType = model.badge {
            switch badgeType {
            case .loading:
                AnyView(
                    BadgeLoadingView(size: IconSize.XSmall())
                        .padding(.bottom, 6)
                        .padding(.trailing, 6)
                )
            case .error:
                AnyView(
                    Image(uiImage: .warningBadge)
                        .padding(.bottom, 4)
                        .padding(.trailing, 4)
                )
            default:
                AnyView(EmptyView())
            }
        } else {
            AnyView(EmptyView())
        }

        ZStack(alignment: alignment) {
            // Background
            switch model.iconBackgroundType {
            case let circle as IconBackgroundTypeCircle:
                Circle()
                    .fill(circle.fillColor)
                    .frame(iconSize: circle.circleSize)
            case let square as IconBackgroundTypeSquare:
                Rectangle()
                    .fill(square.fillColor)
                    .frame(iconSize: square.size)
                    .cornerRadius(CGFloat(square.cornerRadius))
            case _ as IconBackgroundTypeTransient: Color.clear
            default: Color.clear
            }

            // Content
            icon
                .foregroundColor(colorOverride ?? model.iconTint?.color ?? .foreground)
        }.frame(iconSize: model.totalSize)
            .overlay(t, alignment: .bottomTrailing)
    }

    @ViewBuilder
    private var icon: some View {
        let opacity = model.iconOpacity as? Double ?? 1.0
        switch model.iconImage {
        case let image as IconImage.UrlImage:
            if let url = URL(string: image.url) {
                AsyncUrlImageView(
                    url: url,
                    size: model.iconSize,
                    opacity: opacity,
                    fallbackContent: {
                        Image(uiImage: image.fallbackIcon.uiImage)
                            .opacity(opacity)
                            .frame(iconSize: model.iconSize)
                    }
                )
                .frame(iconSize: model.iconSize)

            } else {
                Image(uiImage: image.fallbackIcon.uiImage).opacity(opacity)
            }

        case let icon as IconImage.LocalImage:
            Image(uiImage: icon.icon.uiImage)
                .resizable()
                .opacity(opacity)
                .frame(iconSize: model.iconSize)

        case _ as IconImage.Loader:
            RotatingLoadingIcon(size: model.iconSize, tint: .black)

        default:
            fatalError("\(model.iconImage) not supported")
        }
    }
}

extension View {
    @ViewBuilder
    func frame(iconSize: IconSize) -> some View {
        self.frame(width: iconSize.value.f, height: iconSize.value.f)
    }
}

struct IconViewPreview: PreviewProvider {
    static var previews: some View {
        IconView(
            model:
            IconModel(
                iconImage: .UrlImage(
                    url: "https://upload.wikimedia.org/wikipedia/commons/c/c5/Square_Cash_app_logo.svg",
                    fallbackIcon: .bitcoin
                ),
                iconSize: .Small(),
                iconBackgroundType: IconBackgroundTypeTransient(),
                iconAlignmentInBackground: .center,
                iconTint: nil,
                iconOpacity: nil,
                iconTopSpacing: nil,
                text: nil,
                badge: nil
            )
        )
    }
}

private extension IconBackgroundTypeCircle {
    var fillColor: Color {
        switch color {
        case .foreground10: return .foreground10
        case .primarybackground20: return .bitkeyPrimary.opacity(0.2)
        case .translucentblack: return .black.opacity(0.1)
        case .translucentwhite: return .white.opacity(0.2)
        case .information: return .calloutInformationTrailingIconBackground.opacity(0.25)
        default: return .foreground10
        }
    }
}

private extension IconBackgroundTypeSquare {
    var fillColor: SwiftUI.Color {
        switch color {
        case .default_:
            .calloutDefaultTrailingIconBackground
        case .information:
            .calloutInformationTrailingIconBackground
        case .success:
            .calloutSuccessTrailingIconBackground
        case .warning:
            .calloutWarningTrailingIconBackground
        case .danger:
            .danger
        case .transparent:
            SwiftUI.Color.calloutDefaultTrailingIconBackground.opacity(0)
        default:
            .calloutDefaultTrailingIconBackground
        }
    }
}
