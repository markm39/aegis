import SwiftUI
import PhotosUI
import AVFoundation

/// Camera and photo library integration for capturing images to send to agents.
///
/// Features:
/// - Live camera capture via UIImagePickerController
/// - Photo library selection via PhotosPicker (iOS 16+)
/// - Image preview before sending
/// - Automatic JPEG compression before upload
/// - Configurable compression quality
///
/// Privacy: Camera and photo access require explicit user permission.
/// The app never stores captured images beyond the current session.
struct CameraView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedAgent: String?
    @State private var capturedImage: UIImage?
    @State private var showCamera: Bool = false
    @State private var showPhotoPicker: Bool = false
    @State private var selectedPhotoItem: PhotosPickerItem?
    @State private var isSending: Bool = false
    @State private var statusMessage: String?
    @State private var compressionQuality: Double = 0.7

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                // Agent picker
                if appState.agents.isEmpty {
                    ContentUnavailableView(
                        "No Agents",
                        systemImage: "camera",
                        description: Text("Connect to the daemon to send images to agents.")
                    )
                } else {
                    agentPicker
                    imagePreviewOrPlaceholder
                    captureButtons
                    sendSection
                }
            }
            .padding()
            .navigationTitle("Camera")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $showCamera) {
                CameraCaptureView(image: $capturedImage)
                    .ignoresSafeArea()
            }
            .photosPicker(
                isPresented: $showPhotoPicker,
                selection: $selectedPhotoItem,
                matching: .images
            )
            .onChange(of: selectedPhotoItem) { newItem in
                loadSelectedPhoto(newItem)
            }
        }
    }

    // MARK: - Agent Picker

    private var agentPicker: some View {
        Picker("Agent", selection: $selectedAgent) {
            Text("Select an agent").tag(nil as String?)
            ForEach(appState.agents, id: \.name) { agent in
                Text(agent.name).tag(agent.name as String?)
            }
        }
        .pickerStyle(.segmented)
    }

    // MARK: - Image Preview

    private var imagePreviewOrPlaceholder: some View {
        Group {
            if let image = capturedImage {
                VStack(spacing: 12) {
                    Image(uiImage: image)
                        .resizable()
                        .scaledToFit()
                        .frame(maxHeight: 300)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .shadow(radius: 4)

                    HStack {
                        let size = compressedSize(image: image)
                        Text("Size: \(size)")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Spacer()

                        Button("Clear") {
                            capturedImage = nil
                            selectedPhotoItem = nil
                            statusMessage = nil
                        }
                        .font(.caption)
                        .tint(.red)
                    }

                    // Compression slider
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Quality: \(Int(compressionQuality * 100))%")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Slider(value: $compressionQuality, in: 0.1...1.0, step: 0.1)
                    }
                }
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "photo.on.rectangle.angled")
                        .font(.system(size: 48))
                        .foregroundStyle(.secondary)
                    Text("No image selected")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .frame(height: 200)
                .background(Color(.systemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    // MARK: - Capture Buttons

    private var captureButtons: some View {
        HStack(spacing: 16) {
            Button {
                showCamera = true
            } label: {
                Label("Camera", systemImage: "camera.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)

            Button {
                showPhotoPicker = true
            } label: {
                Label("Library", systemImage: "photo.on.rectangle")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
        }
    }

    // MARK: - Send Section

    private var sendSection: some View {
        VStack(spacing: 8) {
            Button {
                sendImage()
            } label: {
                HStack {
                    if isSending {
                        ProgressView()
                            .controlSize(.small)
                            .tint(.white)
                    }
                    Text(isSending ? "Sending..." : "Send to Agent")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(capturedImage == nil || selectedAgent == nil || isSending)

            if let status = statusMessage {
                Text(status)
                    .font(.caption)
                    .foregroundStyle(status.contains("Error") ? .red : .green)
            }
        }
    }

    // MARK: - Actions

    private func loadSelectedPhoto(_ item: PhotosPickerItem?) {
        guard let item = item else { return }
        Task {
            if let data = try? await item.loadTransferable(type: Data.self),
               let image = UIImage(data: data) {
                capturedImage = image
                statusMessage = nil
            }
        }
    }

    private func sendImage() {
        guard let image = capturedImage,
              let agent = selectedAgent else { return }

        isSending = true
        statusMessage = nil

        Task {
            do {
                guard let jpegData = image.jpegData(compressionQuality: compressionQuality) else {
                    statusMessage = "Error: Failed to compress image"
                    isSending = false
                    return
                }

                let base64 = jpegData.base64EncodedString()
                let message = "[Image attached: \(jpegData.count) bytes, JPEG quality \(Int(compressionQuality * 100))%]\n\(base64)"

                try await appState.sendInput(agentName: agent, text: message)
                statusMessage = "Image sent to \(agent)"
                capturedImage = nil
                selectedPhotoItem = nil
            } catch {
                statusMessage = "Error: \(error.localizedDescription)"
            }
            isSending = false
        }
    }

    private func compressedSize(image: UIImage) -> String {
        guard let data = image.jpegData(compressionQuality: compressionQuality) else {
            return "unknown"
        }
        let bytes = data.count
        if bytes > 1_000_000 {
            return String(format: "%.1f MB", Double(bytes) / 1_000_000.0)
        } else if bytes > 1_000 {
            return String(format: "%.0f KB", Double(bytes) / 1_000.0)
        } else {
            return "\(bytes) B"
        }
    }
}

// MARK: - Camera Capture View (UIKit Bridge)

/// UIViewControllerRepresentable wrapping UIImagePickerController for camera capture.
struct CameraCaptureView: UIViewControllerRepresentable {
    @Binding var image: UIImage?
    @Environment(\.dismiss) private var dismiss

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker = UIImagePickerController()
        picker.sourceType = .camera
        picker.delegate = context.coordinator
        picker.allowsEditing = false
        return picker
    }

    func updateUIViewController(_ uiViewController: UIImagePickerController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    class Coordinator: NSObject, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
        let parent: CameraCaptureView

        init(_ parent: CameraCaptureView) {
            self.parent = parent
        }

        func imagePickerController(
            _ picker: UIImagePickerController,
            didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]
        ) {
            if let uiImage = info[.originalImage] as? UIImage {
                parent.image = uiImage
            }
            parent.dismiss()
        }

        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            parent.dismiss()
        }
    }
}
