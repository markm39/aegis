import SwiftUI

/// Settings view for configuring the daemon connection, authentication, and app preferences.
///
/// Sections:
/// - Pairing: Quick pair/re-pair with daemon
/// - Server: URL configuration with validation
/// - Authentication: API token management (Keychain)
/// - Connection: Status indicator and test
/// - Security: Biometric lock
/// - Notifications: Sound, haptic, and history
/// - Location: Location service settings
/// - About: Version info
///
/// Security:
/// - Server URL is validated (HTTPS required, except localhost)
/// - API token is stored exclusively in the iOS Keychain
/// - Biometric authentication can be enabled to protect app access
/// - Connection test verifies the daemon is reachable
struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var pushManager: PushManager
    @EnvironmentObject var locationService: LocationService

    // Server configuration
    @AppStorage("server_url") private var serverURL: String = "http://localhost:3100"
    @AppStorage("is_paired") private var isPaired: Bool = false
    @State private var urlInput: String = ""
    @State private var urlValidationError: String?

    // Token (displayed as masked, stored in Keychain)
    @State private var tokenInput: String = ""
    @State private var hasToken: Bool = false

    // Connection test
    @State private var isTestingConnection: Bool = false
    @State private var connectionTestResult: ConnectionTestResult?

    // Preferences
    @AppStorage("biometric_enabled") private var biometricEnabled: Bool = false
    @AppStorage("notifications_enabled") private var notificationsEnabled: Bool = true

    // Biometric availability
    @State private var biometricAvailable: Bool = false
    @State private var biometricType: String = "Biometric"

    // Pairing
    @State private var showPairingSheet: Bool = false

    // Notification history
    @State private var showNotificationHistory: Bool = false

    private let tokenManager = TokenManager()

    var body: some View {
        NavigationStack {
            Form {
                pairingSection
                serverSection
                authSection
                connectionSection
                securitySection
                notificationSection
                locationSection
                aboutSection
            }
            .navigationTitle("Settings")
            .onAppear {
                urlInput = serverURL
                hasToken = tokenManager.hasToken()
                checkBiometricAvailability()
            }
            .sheet(isPresented: $showPairingSheet) {
                PairingView()
            }
            .sheet(isPresented: $showNotificationHistory) {
                notificationHistoryView
            }
        }
    }

    // MARK: - Pairing Section

    private var pairingSection: some View {
        Section {
            HStack {
                Image(systemName: isPaired ? "link.circle.fill" : "link.circle")
                    .foregroundStyle(isPaired ? .green : .secondary)
                Text(isPaired ? "Paired" : "Not Paired")
                    .font(.body)
                Spacer()
                Button(isPaired ? "Re-pair" : "Pair Device") {
                    showPairingSheet = true
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
        } header: {
            Label("Device Pairing", systemImage: "link")
        } footer: {
            Text("Scan a QR code or enter a pairing code to connect to your Aegis daemon.")
        }
    }

    // MARK: - Server Section

    private var serverSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                TextField("Server URL", text: $urlInput)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.URL)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .onChange(of: urlInput) { newValue in
                        validateURL(newValue)
                    }

                if let error = urlValidationError {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }

                Button("Save URL") {
                    saveServerURL()
                }
                .disabled(urlValidationError != nil || urlInput.isEmpty)
                .buttonStyle(.bordered)
            }
        } header: {
            Label("Server", systemImage: "server.rack")
        } footer: {
            Text("HTTPS is required for remote servers. HTTP is only allowed for localhost.")
        }
    }

    // MARK: - Auth Section

    private var authSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SecureField("API Token", text: $tokenInput)
                        .textFieldStyle(.roundedBorder)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)

                    if hasToken {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    }
                }

                HStack(spacing: 12) {
                    Button("Save Token") {
                        saveToken()
                    }
                    .disabled(tokenInput.isEmpty)
                    .buttonStyle(.bordered)

                    if hasToken {
                        Button("Remove Token") {
                            removeToken()
                        }
                        .buttonStyle(.bordered)
                        .tint(.red)
                    }
                }
            }
        } header: {
            Label("Authentication", systemImage: "key")
        } footer: {
            Text("The API token is stored securely in the iOS Keychain. It is never written to disk or shared.")
        }
    }

    // MARK: - Connection Section

    private var connectionSection: some View {
        Section {
            HStack {
                Circle()
                    .fill(appState.isConnected ? Color.green : Color.red)
                    .frame(width: 10, height: 10)
                Text(appState.connectionState.displayName)
                    .font(.body)

                Spacer()

                if isTestingConnection {
                    ProgressView()
                        .controlSize(.small)
                }
            }

            if let result = connectionTestResult {
                HStack {
                    Image(systemName: result.success ? "checkmark.circle" : "xmark.circle")
                        .foregroundStyle(result.success ? .green : .red)
                    Text(result.message)
                        .font(.caption)
                        .foregroundStyle(result.success ? .green : .red)
                }
            }

            Button("Test Connection") {
                testConnection()
            }
            .disabled(isTestingConnection)
        } header: {
            Label("Connection", systemImage: "network")
        }
    }

    // MARK: - Security Section

    private var securitySection: some View {
        Section {
            Toggle(isOn: $biometricEnabled) {
                HStack {
                    Image(systemName: biometricType == "Face ID" ? "faceid" : "touchid")
                    Text("Require \(biometricType)")
                }
            }
            .disabled(!biometricAvailable)

            if !biometricAvailable {
                Text("\(biometricType) is not available on this device")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Label("Security", systemImage: "lock.shield")
        } footer: {
            Text("When enabled, \(biometricType) is required each time you open Aegis.")
        }
    }

    // MARK: - Notification Section

    private var notificationSection: some View {
        Section {
            Toggle("Approval Notifications", isOn: $notificationsEnabled)

            Toggle("Sound", isOn: $pushManager.soundEnabled)
                .disabled(!notificationsEnabled)

            Toggle("Haptic Feedback", isOn: $pushManager.hapticEnabled)
                .disabled(!notificationsEnabled)

            Button {
                showNotificationHistory = true
            } label: {
                HStack {
                    Text("Notification History")
                    Spacer()
                    if !pushManager.notificationHistory.isEmpty {
                        Text("\(pushManager.notificationHistory.count)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .foregroundStyle(.primary)
        } header: {
            Label("Notifications", systemImage: "bell")
        } footer: {
            Text("Receive notifications when agents request approval for actions.")
        }
    }

    // MARK: - Location Section

    private var locationSection: some View {
        Section {
            HStack {
                Text("Authorization")
                Spacer()
                Text(locationAuthText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if !locationService.isAuthorized {
                Button("Request Location Access") {
                    locationService.requestAuthorization()
                }
            }

            if !locationService.activeGeofences.isEmpty {
                ForEach(locationService.activeGeofences) { geofence in
                    HStack {
                        Image(systemName: "location.circle")
                            .foregroundStyle(.blue)
                        VStack(alignment: .leading) {
                            Text(geofence.name)
                                .font(.subheadline)
                            Text("\(Int(geofence.radiusMeters))m radius")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .onDelete { indices in
                    for index in indices {
                        let geofence = locationService.activeGeofences[index]
                        locationService.removeGeofence(name: geofence.name)
                    }
                }
            }
        } header: {
            Label("Location", systemImage: "location")
        } footer: {
            Text("Location is shared with agents only when you explicitly send it. Aegis never tracks your location in the background.")
        }
    }

    private var locationAuthText: String {
        switch locationService.authorizationStatus {
        case .authorizedWhenInUse: return "When In Use"
        case .authorizedAlways: return "Always"
        case .denied: return "Denied"
        case .restricted: return "Restricted"
        case .notDetermined: return "Not Set"
        @unknown default: return "Unknown"
        }
    }

    // MARK: - About Section

    private var aboutSection: some View {
        Section {
            HStack {
                Text("Version")
                Spacer()
                Text("0.1.0")
                    .foregroundStyle(.secondary)
            }
            HStack {
                Text("Build")
                Spacer()
                Text("1")
                    .foregroundStyle(.secondary)
            }
        } header: {
            Label("About", systemImage: "info.circle")
        }
    }

    // MARK: - Notification History View

    private var notificationHistoryView: some View {
        NavigationStack {
            List {
                if pushManager.notificationHistory.isEmpty {
                    ContentUnavailableView(
                        "No Notifications",
                        systemImage: "bell.slash",
                        description: Text("Notification history will appear here.")
                    )
                } else {
                    ForEach(pushManager.notificationHistory) { record in
                        HStack(spacing: 12) {
                            Image(systemName: record.category.iconName)
                                .foregroundStyle(record.category.color)
                                .frame(width: 24)

                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(record.subtitle)
                                        .font(.subheadline)
                                        .fontWeight(.medium)
                                    Spacer()
                                    Text(record.timeAgo)
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Text(record.body)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Notification History")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Done") {
                        showNotificationHistory = false
                    }
                }
                if !pushManager.notificationHistory.isEmpty {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button("Clear") {
                            pushManager.clearHistory()
                        }
                        .tint(.red)
                    }
                }
            }
        }
    }

    // MARK: - Actions

    private func validateURL(_ urlString: String) {
        if urlString.isEmpty {
            urlValidationError = nil
            return
        }
        if DaemonClient.validateServerURL(urlString) != nil {
            urlValidationError = nil
        } else {
            urlValidationError = "Invalid URL. Use https:// for remote servers, or http://localhost for development."
        }
    }

    private func saveServerURL() {
        guard let url = DaemonClient.validateServerURL(urlInput) else {
            urlValidationError = "Invalid URL"
            return
        }
        serverURL = urlInput
        appState.reconfigure(baseURL: url)
        urlValidationError = nil
    }

    private func saveToken() {
        let trimmed = tokenInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if tokenManager.setToken(trimmed) {
            hasToken = true
            tokenInput = ""
        }
    }

    private func removeToken() {
        tokenManager.clearToken()
        hasToken = false
        tokenInput = ""
    }

    private func testConnection() {
        isTestingConnection = true
        connectionTestResult = nil
        Task {
            let error = await appState.testConnection()
            await MainActor.run {
                isTestingConnection = false
                if let error = error {
                    connectionTestResult = ConnectionTestResult(success: false, message: error)
                } else {
                    connectionTestResult = ConnectionTestResult(success: true, message: "Connection successful")
                }
            }
        }
    }

    private func checkBiometricAvailability() {
        let (available, type) = BiometricAuth.checkAvailability()
        biometricAvailable = available
        biometricType = type
    }
}

// MARK: - Connection Test Result

private struct ConnectionTestResult {
    let success: Bool
    let message: String
}
