import Foundation
import SwiftUI

/// Manages the bundled aegis daemon process lifecycle.
///
/// Features:
/// - Start/stop daemon from the app
/// - Detect if daemon is already running
/// - Log viewer for daemon output
/// - Status monitoring
@MainActor
final class GatewayManager: ObservableObject {
    /// Whether the daemon process is currently running.
    @Published var isDaemonRunning: Bool = false

    /// Recent log lines from the daemon process.
    @Published var daemonLogs: [String] = []

    /// Error from the last operation.
    @Published var lastError: String?

    /// The managed daemon process, if started by this app.
    private var daemonProcess: Process?

    /// Output pipe for capturing daemon logs.
    private var outputPipe: Pipe?

    /// Polling task for status checks.
    private var statusTask: Task<Void, Never>?

    /// Path to the aegis binary.
    private var aegisBinaryPath: String?

    init() {
        findAegisBinary()
        startStatusMonitoring()
    }

    deinit {
        statusTask?.cancel()
    }

    // MARK: - Binary Discovery

    /// Find the aegis binary in common locations.
    private func findAegisBinary() {
        let candidates = [
            "/usr/local/bin/aegis",
            "/opt/homebrew/bin/aegis",
            NSHomeDirectory() + "/.cargo/bin/aegis",
            "/usr/bin/aegis",
        ]

        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) {
                aegisBinaryPath = path
                return
            }
        }

        // Try to find via `which`
        let whichProcess = Process()
        whichProcess.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        whichProcess.arguments = ["aegis"]
        let pipe = Pipe()
        whichProcess.standardOutput = pipe
        whichProcess.standardError = FileHandle.nullDevice

        do {
            try whichProcess.run()
            whichProcess.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
               !path.isEmpty {
                aegisBinaryPath = path
            }
        } catch {
            // Not found
        }
    }

    // MARK: - Status Monitoring

    /// Periodically check if the daemon is running.
    private func startStatusMonitoring() {
        statusTask?.cancel()
        statusTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.checkDaemonStatus()
                try? await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
            }
        }
    }

    /// Check whether the daemon is reachable.
    private func checkDaemonStatus() async {
        let client = DaemonClient()
        let isRunning = await client.ping()
        self.isDaemonRunning = isRunning
    }

    // MARK: - Daemon Control

    /// Start the daemon process.
    func startDaemon() async {
        guard !isDaemonRunning else {
            lastError = "Daemon is already running"
            return
        }

        guard let binaryPath = aegisBinaryPath else {
            lastError = "Could not find aegis binary. Make sure it is installed and in your PATH."
            return
        }

        do {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: binaryPath)
            process.arguments = ["daemon", "start"]

            // Set up environment
            var env = ProcessInfo.processInfo.environment
            env["AEGIS_DAEMON_FOREGROUND"] = "0"
            process.environment = env

            // Capture output
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            self.outputPipe = pipe

            // Read output asynchronously
            pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                if let line = String(data: data, encoding: .utf8), !line.isEmpty {
                    Task { @MainActor in
                        self?.appendLog(line)
                    }
                }
            }

            process.terminationHandler = { [weak self] proc in
                Task { @MainActor in
                    self?.handleDaemonExit(exitCode: proc.terminationStatus)
                }
            }

            try process.run()
            self.daemonProcess = process
            lastError = nil

            appendLog("Daemon started (PID: \(process.processIdentifier))")

            // Wait a moment, then check status
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            await checkDaemonStatus()
        } catch {
            lastError = "Failed to start daemon: \(error.localizedDescription)"
            appendLog("Error: \(error.localizedDescription)")
        }
    }

    /// Stop the daemon process.
    func stopDaemon() async {
        // Try graceful shutdown via API first
        let client = DaemonClient()
        do {
            try await client.stopDaemon()
            appendLog("Sent shutdown command to daemon")
        } catch {
            // API failed, try killing the process directly
            if let process = daemonProcess, process.isRunning {
                process.terminate()
                appendLog("Terminated daemon process")
            } else {
                lastError = "Failed to stop daemon: \(error.localizedDescription)"
            }
        }

        // Wait and recheck
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        await checkDaemonStatus()
    }

    /// Restart the daemon.
    func restartDaemon() async {
        await stopDaemon()
        try? await Task.sleep(nanoseconds: 1_000_000_000)
        await startDaemon()
    }

    // MARK: - Log Management

    /// Append a log line.
    private func appendLog(_ line: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        daemonLogs.append("[\(timestamp)] \(line)")

        // Keep only last 500 lines
        if daemonLogs.count > 500 {
            daemonLogs = Array(daemonLogs.suffix(500))
        }
    }

    /// Clear all logs.
    func clearLogs() {
        daemonLogs.removeAll()
    }

    /// Handle daemon process exit.
    private func handleDaemonExit(exitCode: Int32) {
        isDaemonRunning = false
        daemonProcess = nil
        outputPipe?.fileHandleForReading.readabilityHandler = nil
        outputPipe = nil

        if exitCode == 0 {
            appendLog("Daemon exited normally")
        } else {
            appendLog("Daemon exited with code \(exitCode)")
            lastError = "Daemon exited with code \(exitCode)"
        }
    }
}
