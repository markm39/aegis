import SwiftUI
import AVFoundation

/// Pairing flow for connecting the iOS app to a desktop Aegis daemon.
///
/// Supports two pairing methods:
/// - QR code scanning: Camera-based scan of a QR code displayed by the daemon
/// - Manual entry: Type or paste a pairing code as fallback
///
/// The pairing code contains:
/// - Server URL (base URL for the daemon HTTP API)
/// - Authentication token (stored in Keychain after pairing)
///
/// After successful pairing, connection info is persisted securely:
/// - Server URL in UserDefaults (not sensitive)
/// - Auth token in iOS Keychain (encrypted, device-only)
///
/// The view also shows connection status and supports re-pairing.
struct PairingView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var mode: PairingMode = .qrCode
    @State private var manualCode: String = ""
    @State private var isPairing: Bool = false
    @State private var pairingError: String?
    @State private var pairingSuccess: Bool = false
    @State private var showScanner: Bool = false
    @State private var scannedCode: String?

    @AppStorage("server_url") private var serverURL: String = "http://localhost:3100"
    @AppStorage("is_paired") private var isPaired: Bool = false

    private let tokenManager = TokenManager()

    enum PairingMode: String, CaseIterable {
        case qrCode = "QR Code"
        case manual = "Manual"
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                // Header
                headerSection

                // Mode picker
                Picker("Method", selection: $mode) {
                    ForEach(PairingMode.allCases, id: \.self) { m in
                        Text(m.rawValue).tag(m)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)

                // Content based on mode
                switch mode {
                case .qrCode:
                    qrCodeSection
                case .manual:
                    manualEntrySection
                }

                Spacer()

                // Status
                if pairingSuccess {
                    successBanner
                }
                if let error = pairingError {
                    errorBanner(error)
                }
            }
            .navigationTitle("Pair Device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
            .sheet(isPresented: $showScanner) {
                QRScannerView(scannedCode: $scannedCode)
                    .ignoresSafeArea()
            }
            .onChange(of: scannedCode) { code in
                if let code = code {
                    processPairingCode(code)
                }
            }
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        VStack(spacing: 12) {
            Image(systemName: "link.circle.fill")
                .font(.system(size: 56))
                .foregroundStyle(.blue)

            Text("Connect to Aegis Daemon")
                .font(.title3)
                .fontWeight(.bold)

            Text("Scan the QR code shown by your daemon, or enter the pairing code manually.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .padding(.top)
    }

    // MARK: - QR Code Section

    private var qrCodeSection: some View {
        VStack(spacing: 16) {
            Button {
                showScanner = true
            } label: {
                VStack(spacing: 12) {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.system(size: 80))
                    Text("Tap to Scan QR Code")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
                .frame(height: 200)
                .background(Color(.systemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 16))
            }
            .buttonStyle(.plain)
            .padding(.horizontal)

            Text("Run 'aegis pair --show-qr' on your desktop to display the QR code.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
    }

    // MARK: - Manual Entry Section

    private var manualEntrySection: some View {
        VStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Pairing Code")
                    .font(.subheadline)
                    .fontWeight(.medium)

                TextField("aegis://host:port/token", text: $manualCode)
                    .textFieldStyle(.roundedBorder)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .keyboardType(.URL)

                Text("Format: aegis://host:port/token")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal)

            Button {
                processPairingCode(manualCode)
            } label: {
                HStack {
                    if isPairing {
                        ProgressView()
                            .controlSize(.small)
                            .tint(.white)
                    }
                    Text(isPairing ? "Connecting..." : "Connect")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(manualCode.isEmpty || isPairing)
            .padding(.horizontal)

            Text("Run 'aegis pair --show-code' on your desktop to get the pairing code.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
    }

    // MARK: - Status Banners

    private var successBanner: some View {
        HStack {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
            Text("Paired successfully")
                .fontWeight(.medium)
            Spacer()
            Button("Done") {
                dismiss()
            }
            .buttonStyle(.bordered)
        }
        .padding()
        .background(Color.green.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .padding(.horizontal)
    }

    private func errorBanner(_ message: String) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            Text(message)
                .font(.caption)
                .foregroundStyle(.red)
            Spacer()
            Button("Dismiss") {
                pairingError = nil
            }
            .font(.caption)
        }
        .padding()
        .background(Color.red.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .padding(.horizontal)
    }

    // MARK: - Pairing Logic

    /// Parse and process a pairing code.
    ///
    /// Expected format: `aegis://host:port/token`
    /// Also accepts: `https://host:port` with separate token, or raw JSON.
    private func processPairingCode(_ code: String) {
        isPairing = true
        pairingError = nil
        pairingSuccess = false

        Task {
            do {
                let (url, token) = try parsePairingCode(code)

                // Validate the URL
                guard DaemonClient.validateServerURL(url.absoluteString) != nil else {
                    throw PairingError.invalidURL(url.absoluteString)
                }

                // Store the token in Keychain
                if let token = token {
                    let manager = TokenManager()
                    guard manager.setToken(token) else {
                        throw PairingError.keychainError
                    }
                }

                // Save the server URL
                serverURL = url.absoluteString

                // Reconfigure the app state with the new URL
                appState.reconfigure(baseURL: url)

                // Test the connection
                if let error = await appState.testConnection() {
                    throw PairingError.connectionFailed(error)
                }

                isPaired = true
                pairingSuccess = true
            } catch {
                pairingError = error.localizedDescription
            }

            isPairing = false
        }
    }

    /// Parse a pairing code into a URL and optional token.
    private func parsePairingCode(_ code: String) throws -> (URL, String?) {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)

        // Try aegis:// scheme: aegis://host:port/token
        if trimmed.hasPrefix("aegis://") {
            let withoutScheme = String(trimmed.dropFirst("aegis://".count))
            let parts = withoutScheme.split(separator: "/", maxSplits: 1)
            guard let hostPort = parts.first else {
                throw PairingError.invalidCode
            }

            let urlString = "http://\(hostPort)"
            guard let url = URL(string: urlString) else {
                throw PairingError.invalidCode
            }

            let token = parts.count > 1 ? String(parts[1]) : nil
            return (url, token)
        }

        // Try JSON format: {"url": "...", "token": "..."}
        if trimmed.hasPrefix("{"),
           let data = trimmed.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
           let urlString = json["url"],
           let url = URL(string: urlString) {
            return (url, json["token"])
        }

        // Try raw URL
        if let url = URL(string: trimmed), url.scheme != nil {
            return (url, nil)
        }

        throw PairingError.invalidCode
    }
}

// MARK: - Pairing Errors

enum PairingError: LocalizedError {
    case invalidCode
    case invalidURL(String)
    case keychainError
    case connectionFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidCode:
            return "Invalid pairing code. Expected format: aegis://host:port/token"
        case .invalidURL(let url):
            return "Invalid server URL: \(url). HTTPS required for remote servers."
        case .keychainError:
            return "Failed to store authentication token in Keychain."
        case .connectionFailed(let msg):
            return "Connection test failed: \(msg)"
        }
    }
}

// MARK: - QR Code Scanner

/// Camera-based QR code scanner using AVFoundation.
struct QRScannerView: UIViewControllerRepresentable {
    @Binding var scannedCode: String?
    @Environment(\.dismiss) private var dismiss

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    class Coordinator: NSObject, QRScannerDelegate {
        let parent: QRScannerView

        init(_ parent: QRScannerView) {
            self.parent = parent
        }

        func didScanCode(_ code: String) {
            parent.scannedCode = code
            parent.dismiss()
        }

        func didFailWithError(_ error: String) {
            parent.dismiss()
        }
    }
}

/// Protocol for QR scanner callbacks.
protocol QRScannerDelegate: AnyObject {
    func didScanCode(_ code: String)
    func didFailWithError(_ error: String)
}

/// UIKit view controller for QR code scanning.
final class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    weak var delegate: QRScannerDelegate?
    private var captureSession: AVCaptureSession?
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasScanned = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        setupCamera()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.layer.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        startSession()
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        stopSession()
    }

    private func setupCamera() {
        let session = AVCaptureSession()

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else {
            delegate?.didFailWithError("Camera not available")
            return
        }

        if session.canAddInput(input) {
            session.addInput(input)
        }

        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
            output.metadataObjectTypes = [.qr]
        }

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.layer.bounds
        view.layer.addSublayer(preview)

        // Overlay with scan frame indicator
        let overlayView = QROverlayView(frame: view.bounds)
        overlayView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(overlayView)

        self.captureSession = session
        self.previewLayer = preview
    }

    private func startSession() {
        guard let session = captureSession, !session.isRunning else { return }
        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }
    }

    private func stopSession() {
        guard let session = captureSession, session.isRunning else { return }
        session.stopRunning()
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !hasScanned,
              let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              object.type == .qr,
              let code = object.stringValue else {
            return
        }

        hasScanned = true

        // Haptic feedback
        let generator = UINotificationFeedbackGenerator()
        generator.notificationOccurred(.success)

        stopSession()
        delegate?.didScanCode(code)
    }
}

/// Overlay view that draws a scanning frame indicator on the camera preview.
private final class QROverlayView: UIView {
    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
        isOpaque = false
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) not implemented")
    }

    override func draw(_ rect: CGRect) {
        guard let ctx = UIGraphicsGetCurrentContext() else { return }

        // Semi-transparent overlay
        ctx.setFillColor(UIColor.black.withAlphaComponent(0.5).cgColor)
        ctx.fill(rect)

        // Clear center square for scanning area
        let side = min(rect.width, rect.height) * 0.65
        let scanRect = CGRect(
            x: (rect.width - side) / 2,
            y: (rect.height - side) / 2,
            width: side,
            height: side
        )
        ctx.clear(scanRect)

        // Draw corner brackets
        let bracketLength: CGFloat = 30
        let bracketWidth: CGFloat = 4
        ctx.setStrokeColor(UIColor.white.cgColor)
        ctx.setLineWidth(bracketWidth)

        let corners: [(CGPoint, CGPoint, CGPoint)] = [
            // Top-left
            (CGPoint(x: scanRect.minX, y: scanRect.minY + bracketLength),
             CGPoint(x: scanRect.minX, y: scanRect.minY),
             CGPoint(x: scanRect.minX + bracketLength, y: scanRect.minY)),
            // Top-right
            (CGPoint(x: scanRect.maxX - bracketLength, y: scanRect.minY),
             CGPoint(x: scanRect.maxX, y: scanRect.minY),
             CGPoint(x: scanRect.maxX, y: scanRect.minY + bracketLength)),
            // Bottom-left
            (CGPoint(x: scanRect.minX, y: scanRect.maxY - bracketLength),
             CGPoint(x: scanRect.minX, y: scanRect.maxY),
             CGPoint(x: scanRect.minX + bracketLength, y: scanRect.maxY)),
            // Bottom-right
            (CGPoint(x: scanRect.maxX - bracketLength, y: scanRect.maxY),
             CGPoint(x: scanRect.maxX, y: scanRect.maxY),
             CGPoint(x: scanRect.maxX, y: scanRect.maxY - bracketLength)),
        ]

        for (start, mid, end) in corners {
            ctx.move(to: start)
            ctx.addLine(to: mid)
            ctx.addLine(to: end)
            ctx.strokePath()
        }
    }
}
