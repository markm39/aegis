import SwiftUI
import AVFoundation

/// Voice interaction mode for the overlay.
enum VoiceMode: String, CaseIterable {
    case pushToTalk = "Push to Talk"
    case voiceActivated = "Voice Activated"
}

/// Current state of the voice pipeline.
enum VoiceState: Equatable {
    case idle
    case listening
    case processing
    case speaking
    case error(String)

    var displayName: String {
        switch self {
        case .idle: return "Ready"
        case .listening: return "Listening..."
        case .processing: return "Processing..."
        case .speaking: return "Speaking..."
        case .error(let msg): return "Error: \(msg)"
        }
    }

    var isListening: Bool {
        if case .listening = self { return true }
        return false
    }
}

/// Minimal floating overlay for voice mode.
///
/// Features:
/// - Microphone indicator (listening/processing/speaking)
/// - Waveform visualization
/// - Dismiss with Esc or click outside
/// - Integrates with system audio via AVAudioEngine
/// - Push-to-talk or voice-activated modes
struct VoiceOverlay: View {
    @ObservedObject var fleetState: FleetState
    @StateObject private var voiceEngine = VoiceEngine()
    @State private var selectedAgent: String?
    @State private var voiceMode: VoiceMode = .pushToTalk
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 16) {
            // Agent selector
            HStack {
                Picker("Agent:", selection: $selectedAgent) {
                    Text("Select...").tag(nil as String?)
                    ForEach(fleetState.agents, id: \.name) { agent in
                        Text(agent.name).tag(agent.name as String?)
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .padding(.horizontal)

            // Voice state indicator
            voiceStateIndicator

            // Waveform visualization
            WaveformView(levels: voiceEngine.audioLevels)
                .frame(height: 60)
                .padding(.horizontal)

            // Mode selector
            Picker("Mode:", selection: $voiceMode) {
                ForEach(VoiceMode.allCases, id: \.self) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)
            .onChange(of: voiceMode) { newMode in
                voiceEngine.voiceMode = newMode
            }

            // Controls
            voiceControls

            // Status text
            Text(voiceEngine.voiceState.displayName)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding()
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    // MARK: - Voice State Indicator

    private var voiceStateIndicator: some View {
        ZStack {
            // Outer pulsing ring
            Circle()
                .stroke(stateColor.opacity(0.3), lineWidth: 3)
                .frame(width: 80, height: 80)
                .scaleEffect(voiceEngine.voiceState.isListening ? 1.2 : 1.0)
                .animation(
                    voiceEngine.voiceState.isListening
                        ? .easeInOut(duration: 1).repeatForever(autoreverses: true)
                        : .default,
                    value: voiceEngine.voiceState.isListening
                )

            // Inner circle
            Circle()
                .fill(stateColor)
                .frame(width: 60, height: 60)

            // Icon
            Image(systemName: stateIcon)
                .font(.title)
                .foregroundStyle(.white)
        }
    }

    private var stateColor: Color {
        switch voiceEngine.voiceState {
        case .idle: return .gray
        case .listening: return .red
        case .processing: return .orange
        case .speaking: return .green
        case .error: return .red
        }
    }

    private var stateIcon: String {
        switch voiceEngine.voiceState {
        case .idle: return "mic"
        case .listening: return "mic.fill"
        case .processing: return "ellipsis"
        case .speaking: return "speaker.wave.2.fill"
        case .error: return "exclamationmark.triangle"
        }
    }

    // MARK: - Controls

    private var voiceControls: some View {
        HStack(spacing: 16) {
            if voiceMode == .pushToTalk {
                // Push-to-talk button
                Button {
                    // Toggle on press
                } label: {
                    Label("Hold to Talk", systemImage: "mic.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(voiceEngine.voiceState.isListening ? .red : .blue)
                .simultaneousGesture(
                    DragGesture(minimumDistance: 0)
                        .onChanged { _ in
                            if !voiceEngine.voiceState.isListening {
                                voiceEngine.startListening()
                            }
                        }
                        .onEnded { _ in
                            voiceEngine.stopListening()
                            sendTranscription()
                        }
                )
            } else {
                // Voice-activated toggle
                Button {
                    if voiceEngine.voiceState.isListening {
                        voiceEngine.stopListening()
                        sendTranscription()
                    } else {
                        voiceEngine.startListening()
                    }
                } label: {
                    Label(
                        voiceEngine.voiceState.isListening ? "Stop" : "Start",
                        systemImage: voiceEngine.voiceState.isListening ? "stop.fill" : "mic.fill"
                    )
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(voiceEngine.voiceState.isListening ? .red : .blue)
            }

            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title2)
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
        }
        .padding(.horizontal)
    }

    private func sendTranscription() {
        guard let agentName = selectedAgent,
              !voiceEngine.transcription.isEmpty else { return }

        let text = voiceEngine.transcription
        voiceEngine.transcription = ""

        Task {
            try? await fleetState.sendInput(agentName: agentName, text: text)
        }
    }
}

// MARK: - Voice Engine

/// Manages audio capture and processing using AVAudioEngine.
@MainActor
final class VoiceEngine: ObservableObject {
    @Published var voiceState: VoiceState = .idle
    @Published var audioLevels: [Float] = Array(repeating: 0, count: 20)
    @Published var transcription: String = ""
    var voiceMode: VoiceMode = .pushToTalk

    private var audioEngine: AVAudioEngine?
    private var levelTimer: Task<Void, Never>?

    init() {
        // Audio engine is created on demand
    }

    /// Start capturing audio.
    func startListening() {
        guard !voiceState.isListening else { return }

        do {
            let engine = AVAudioEngine()
            let inputNode = engine.inputNode
            let format = inputNode.outputFormat(forBus: 0)

            inputNode.installTap(onBus: 0, bufferSize: 1024, format: format) { [weak self] buffer, _ in
                Task { @MainActor in
                    self?.processAudioBuffer(buffer)
                }
            }

            try engine.start()
            self.audioEngine = engine
            voiceState = .listening

            // Start level monitoring
            startLevelMonitoring()
        } catch {
            voiceState = .error(error.localizedDescription)
        }
    }

    /// Stop capturing audio.
    func stopListening() {
        audioEngine?.inputNode.removeTap(onBus: 0)
        audioEngine?.stop()
        audioEngine = nil
        levelTimer?.cancel()
        levelTimer = nil

        if voiceState.isListening {
            voiceState = .processing
            // Simulate processing delay, then return to idle
            Task {
                try? await Task.sleep(nanoseconds: 500_000_000)
                voiceState = .idle
            }
        }
    }

    /// Process an audio buffer to extract levels for visualization.
    private func processAudioBuffer(_ buffer: AVAudioPCMBuffer) {
        guard let channelData = buffer.floatChannelData?[0] else { return }
        let frameCount = Int(buffer.frameLength)

        // Calculate RMS level
        var sum: Float = 0
        for i in 0..<frameCount {
            let sample = channelData[i]
            sum += sample * sample
        }
        let rms = sqrt(sum / Float(frameCount))
        let level = min(1.0, rms * 5.0) // Scale up for visibility

        // Shift levels and add new one
        audioLevels.removeFirst()
        audioLevels.append(level)
    }

    /// Periodically update levels (smooth decay when not getting audio).
    private func startLevelMonitoring() {
        levelTimer?.cancel()
        levelTimer = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 50_000_000) // 50ms
                guard let self = self else { break }
                // Apply decay to levels
                for i in 0..<self.audioLevels.count {
                    self.audioLevels[i] *= 0.95
                }
            }
        }
    }
}

// MARK: - Waveform Visualization

/// Animated waveform visualization from audio levels.
struct WaveformView: View {
    let levels: [Float]

    var body: some View {
        GeometryReader { geometry in
            HStack(alignment: .center, spacing: 2) {
                ForEach(0..<levels.count, id: \.self) { index in
                    let level = CGFloat(levels[index])
                    let maxHeight = geometry.size.height
                    let barHeight = max(4, level * maxHeight)

                    RoundedRectangle(cornerRadius: 2)
                        .fill(barColor(for: level))
                        .frame(width: max(2, geometry.size.width / CGFloat(levels.count) - 2))
                        .frame(height: barHeight)
                        .animation(.easeOut(duration: 0.1), value: levels[index])
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func barColor(for level: CGFloat) -> Color {
        if level > 0.7 {
            return .red
        } else if level > 0.3 {
            return .orange
        } else {
            return .green
        }
    }
}
