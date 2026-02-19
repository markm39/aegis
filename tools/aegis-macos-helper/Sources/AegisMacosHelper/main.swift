import Foundation
import AppKit
import CoreGraphics

struct Request: Codable {
    let op: String
    let region: Region?
    let x: Int?
    let y: Int?
    let button: String?
    let text: String?
    let key: String?
    let app_id: String?
    let window_id: UInt32?
}

struct Region: Codable {
    let x: Int
    let y: Int
    let width: Int
    let height: Int
}

struct Response: Codable {
    let ok: Bool
    let error: String?
    let width: Int?
    let height: Int?
    let rgba_base64: String?
}

func writeResponse(_ response: Response) {
    let encoder = JSONEncoder()
    if let data = try? encoder.encode(response) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write("\n".data(using: .utf8)!)
    }
}

func readRequest() -> Request? {
    guard let line = readLine() else { return nil }
    let decoder = JSONDecoder()
    return try? decoder.decode(Request.self, from: Data(line.utf8))
}

func capture(region: Region?) -> Response {
    let rect: CGRect
    if let region = region {
        rect = CGRect(x: region.x, y: region.y, width: region.width, height: region.height)
    } else {
        let displayId = CGMainDisplayID()
        rect = CGRect(x: 0, y: 0, width: Int(CGDisplayPixelsWide(displayId)), height: Int(CGDisplayPixelsHigh(displayId)))
    }

    guard let image = CGWindowListCreateImage(rect, .optionOnScreenOnly, kCGNullWindowID, .bestResolution) else {
        return Response(ok: false, error: "capture failed", width: nil, height: nil, rgba_base64: nil)
    }

    let width = image.width
    let height = image.height
    let bytesPerPixel = 4
    let bytesPerRow = bytesPerPixel * width
    let bufferSize = bytesPerRow * height
    var buffer = [UInt8](repeating: 0, count: bufferSize)

    let colorSpace = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(
        data: &buffer,
        width: width,
        height: height,
        bitsPerComponent: 8,
        bytesPerRow: bytesPerRow,
        space: colorSpace,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else {
        return Response(ok: false, error: "context failed", width: nil, height: nil, rgba_base64: nil)
    }

    ctx.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
    let data = Data(buffer)
    let b64 = data.base64EncodedString()
    return Response(ok: true, error: nil, width: width, height: height, rgba_base64: b64)
}

func postMouseEvent(type: CGEventType, x: Int, y: Int, button: CGMouseButton) {
    if let event = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: CGPoint(x: x, y: y), mouseButton: button) {
        event.post(tap: .cghidEventTap)
    }
}

func mouseMove(x: Int, y: Int) -> Response {
    postMouseEvent(type: .mouseMoved, x: x, y: y, button: .left)
    return Response(ok: true, error: nil, width: nil, height: nil, rgba_base64: nil)
}

func mouseClick(x: Int, y: Int, button: String?) -> Response {
    let btn: CGMouseButton
    let down: CGEventType
    let up: CGEventType
    switch button?.lowercased() {
    case "right":
        btn = .right
        down = .rightMouseDown
        up = .rightMouseUp
    case "middle":
        btn = .center
        down = .otherMouseDown
        up = .otherMouseUp
    default:
        btn = .left
        down = .leftMouseDown
        up = .leftMouseUp
    }
    postMouseEvent(type: down, x: x, y: y, button: btn)
    postMouseEvent(type: up, x: x, y: y, button: btn)
    return Response(ok: true, error: nil, width: nil, height: nil, rgba_base64: nil)
}

func mouseDown(x: Int, y: Int, button: String?) -> Response {
    let btn: CGMouseButton
    let down: CGEventType
    switch button?.lowercased() {
    case "right":
        btn = .right
        down = .rightMouseDown
    case "middle":
        btn = .center
        down = .otherMouseDown
    default:
        btn = .left
        down = .leftMouseDown
    }
    postMouseEvent(type: down, x: x, y: y, button: btn)
    return Response(ok: true, error: nil, width: nil, height: nil, rgba_base64: nil)
}

func mouseUp(x: Int, y: Int, button: String?) -> Response {
    let btn: CGMouseButton
    let up: CGEventType
    switch button?.lowercased() {
    case "right":
        btn = .right
        up = .rightMouseUp
    case "middle":
        btn = .center
        up = .otherMouseUp
    default:
        btn = .left
        up = .leftMouseUp
    }
    postMouseEvent(type: up, x: x, y: y, button: btn)
    return Response(ok: true, error: nil, width: nil, height: nil, rgba_base64: nil)
}

func postUnicode(_ text: String) -> Bool {
    let chars = Array(text.utf16)
    if let down = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: true),
       let up = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: false) {
        down.keyboardSetUnicodeString(stringLength: chars.count, unicodeString: chars)
        up.keyboardSetUnicodeString(stringLength: chars.count, unicodeString: chars)
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
        return true
    }
    return false
}

func keyPress(key: String?) -> Response {
    guard let key = key, !key.isEmpty else {
        return Response(ok: false, error: "missing key", width: nil, height: nil, rgba_base64: nil)
    }
    if postUnicode(key) {
        return Response(ok: true, error: nil, width: nil, height: nil, rgba_base64: nil)
    }
    return Response(ok: false, error: "key event failed", width: nil, height: nil, rgba_base64: nil)
}

func typeText(text: String?) -> Response {
    guard let text = text else {
        return Response(ok: false, error: "missing text", width: nil, height: nil, rgba_base64: nil)
    }
    if postUnicode(text) {
        return Response(ok: true, error: nil, width: nil, height: nil, rgba_base64: nil)
    }
    return Response(ok: false, error: "type event failed", width: nil, height: nil, rgba_base64: nil)
}

func focus(appId: String?) -> Response {
    guard let appId = appId else {
        return Response(ok: false, error: "missing app_id", width: nil, height: nil, rgba_base64: nil)
    }
    let apps = NSRunningApplication.runningApplications(withBundleIdentifier: appId)
    if let app = apps.first {
        let ok = app.activate(options: [.activateIgnoringOtherApps, .activateAllWindows])
        return Response(ok: ok, error: ok ? nil : "activate failed", width: nil, height: nil, rgba_base64: nil)
    }
    return Response(ok: false, error: "app not found", width: nil, height: nil, rgba_base64: nil)
}

while let req = readRequest() {
    switch req.op {
    case "capture":
        writeResponse(capture(region: req.region))
    case "mouse_move":
        writeResponse(mouseMove(x: req.x ?? 0, y: req.y ?? 0))
    case "mouse_click":
        writeResponse(mouseClick(x: req.x ?? 0, y: req.y ?? 0, button: req.button))
    case "mouse_down":
        writeResponse(mouseDown(x: req.x ?? 0, y: req.y ?? 0, button: req.button))
    case "mouse_up":
        writeResponse(mouseUp(x: req.x ?? 0, y: req.y ?? 0, button: req.button))
    case "key_press":
        writeResponse(keyPress(key: req.key))
    case "type_text":
        writeResponse(typeText(text: req.text))
    case "focus":
        writeResponse(focus(appId: req.app_id))
    default:
        writeResponse(Response(ok: false, error: "unknown op", width: nil, height: nil, rgba_base64: nil))
    }
}
