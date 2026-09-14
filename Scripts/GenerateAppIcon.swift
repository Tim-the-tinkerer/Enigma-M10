#!/usr/bin/env swift
import AppKit
import Foundation
import ImageIO
import UniformTypeIdentifiers

func renderIcon(size: Int) -> CGImage? {
    let s = CGFloat(size)
    let colorSpace = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(
        data: nil,
        width: size,
        height: size,
        bitsPerComponent: 8,
        bytesPerRow: size * 4,
        space: colorSpace,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else { return nil }

    ctx.setAllowsAntialiasing(true)
    ctx.setShouldAntialias(true)
    ctx.interpolationQuality = .high

    let margin = s * 0.06
    let corner = s * 0.22
    let rect = CGRect(x: margin, y: margin, width: s - margin * 2, height: s - margin * 2)
    let path = CGPath(roundedRect: rect, cornerWidth: corner, cornerHeight: corner, transform: nil)

    ctx.saveGState()
    ctx.addPath(path)
    ctx.clip()

    let colors = [
        CGColor(srgbRed: 0.10, green: 0.09, blue: 0.07, alpha: 1),
        CGColor(srgbRed: 0.16, green: 0.14, blue: 0.10, alpha: 1),
        CGColor(srgbRed: 0.08, green: 0.12, blue: 0.06, alpha: 1),
        CGColor(srgbRed: 0.07, green: 0.07, blue: 0.05, alpha: 1),
    ] as CFArray
    if let gradient = CGGradient(colorsSpace: colorSpace, colors: colors, locations: [0, 0.35, 0.7, 1]) {
        ctx.drawLinearGradient(
            gradient,
            start: CGPoint(x: rect.minX, y: rect.maxY),
            end: CGPoint(x: rect.maxX, y: rect.minY),
            options: []
        )
    }

    drawRotors(in: ctx, size: s, bounds: rect)
    drawLampRow(in: ctx, size: s, bounds: rect)

    if let highlight = CGGradient(
        colorsSpace: colorSpace,
        colors: [
            CGColor(srgbRed: 0.70, green: 0.95, blue: 0.35, alpha: 0.18),
            CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 0),
        ] as CFArray,
        locations: [0, 1]
    ) {
        ctx.drawLinearGradient(
            highlight,
            start: CGPoint(x: rect.midX, y: rect.maxY),
            end: CGPoint(x: rect.midX, y: rect.midY),
            options: []
        )
    }

    ctx.restoreGState()

    ctx.setStrokeColor(CGColor(srgbRed: 0.64, green: 0.89, blue: 0.21, alpha: 0.55))
    ctx.setLineWidth(max(1.0, s * 0.012))
    ctx.addPath(path)
    ctx.strokePath()

    drawMark(in: ctx, size: s, bounds: rect)
    return ctx.makeImage()
}

func drawRotors(in ctx: CGContext, size s: CGFloat, bounds: CGRect) {
    let count = 10
    let insetX = bounds.width * 0.10
    let top = bounds.maxY - bounds.height * 0.28
    let height = bounds.height * 0.22
    let gap = bounds.width * 0.012
    let totalGap = gap * CGFloat(count - 1)
    let width = (bounds.width - insetX * 2 - totalGap) / CGFloat(count)
    let letters = Array("M10ENIGMAX")

    for i in 0..<count {
        let x = bounds.minX + insetX + CGFloat(i) * (width + gap)
        let r = CGRect(x: x, y: top - height, width: width, height: height)
        let rotorPath = CGPath(roundedRect: r, cornerWidth: width * 0.25, cornerHeight: width * 0.25, transform: nil)
        ctx.setFillColor(CGColor(srgbRed: 0.18, green: 0.17, blue: 0.13, alpha: 1))
        ctx.addPath(rotorPath)
        ctx.fillPath()
        ctx.setStrokeColor(CGColor(srgbRed: 0.64, green: 0.89, blue: 0.21, alpha: i == 2 ? 0.95 : 0.35))
        ctx.setLineWidth(max(0.6, s * 0.006))
        ctx.addPath(rotorPath)
        ctx.strokePath()

        if s >= 64 {
            let letter = String(letters[i])
            let fontSize = max(6, width * 0.72)
            let font = CTFontCreateWithName("Menlo-Bold" as CFString, fontSize, nil)
            let attrs: [NSAttributedString.Key: Any] = [
                .font: font,
                .foregroundColor: NSColor(srgbRed: 0.64, green: 0.89, blue: 0.21, alpha: 1)
            ]
            let attr = NSAttributedString(string: letter, attributes: attrs)
            let line = CTLineCreateWithAttributedString(attr)
            let lineBounds = CTLineGetBoundsWithOptions(line, .useGlyphPathBounds)
            ctx.saveGState()
            ctx.textPosition = CGPoint(
                x: r.midX - lineBounds.midX,
                y: r.midY - lineBounds.midY
            )
            CTLineDraw(line, ctx)
            ctx.restoreGState()
        }
    }
}

func drawLampRow(in ctx: CGContext, size s: CGFloat, bounds: CGRect) {
    let count = 10
    let y = bounds.minY + bounds.height * 0.22
    let radius = max(1.2, s * 0.018)
    let span = bounds.width * 0.62
    let startX = bounds.midX - span / 2
    for i in 0..<count {
        let x = startX + span * CGFloat(i) / CGFloat(count - 1)
        let lit = i == 0 || i == 3 || i == 9
        ctx.setFillColor(CGColor(
            srgbRed: 0.64,
            green: 0.89,
            blue: 0.21,
            alpha: lit ? 0.9 : 0.22
        ))
        ctx.fillEllipse(in: CGRect(x: x - radius, y: y - radius, width: radius * 2, height: radius * 2))
    }
}

func drawMark(in ctx: CGContext, size s: CGFloat, bounds: CGRect) {
    let text = "M10"
    let fontSize = s * 0.22
    let font = CTFontCreateWithName("Menlo-Bold" as CFString, fontSize, nil)
    let attrs: [NSAttributedString.Key: Any] = [
        .font: font,
        .foregroundColor: NSColor(srgbRed: 0.72, green: 0.94, blue: 0.32, alpha: 0.96)
    ]
    let attr = NSAttributedString(string: text, attributes: attrs)
    let line = CTLineCreateWithAttributedString(attr)
    let lineBounds = CTLineGetBoundsWithOptions(line, .useGlyphPathBounds)
    ctx.saveGState()
    ctx.textPosition = CGPoint(
        x: bounds.midX - lineBounds.midX,
        y: bounds.minY + bounds.height * 0.34 - lineBounds.midY
    )
    CTLineDraw(line, ctx)
    ctx.restoreGState()
}

func writePNG(_ image: CGImage, to url: URL) throws {
    let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, image, nil)
    guard CGImageDestinationFinalize(dest) else {
        throw NSError(domain: "GenerateAppIcon", code: 1)
    }
}

let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let assets = root.appendingPathComponent("Assets")
let iconset = assets.appendingPathComponent("AppIcon.iconset")
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

let entries: [(name: String, size: Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]

for entry in entries {
    guard let image = renderIcon(size: entry.size) else {
        fputs("error: failed to render \(entry.size)\n", stderr)
        exit(1)
    }
    try writePNG(image, to: iconset.appendingPathComponent(entry.name))
}

if let image = renderIcon(size: 1024) {
    try writePNG(image, to: assets.appendingPathComponent("AppIcon-1024.png"))
}

let icns = assets.appendingPathComponent("AppIcon.icns")
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
process.arguments = ["-c", "icns", "-o", icns.path, iconset.path]
try process.run()
process.waitUntilExit()
guard process.terminationStatus == 0 else {
    fputs("error: iconutil failed\n", stderr)
    exit(1)
}
print("Wrote \(icns.path)")
