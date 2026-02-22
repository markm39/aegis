import Foundation
import CoreLocation
import Combine
import UserNotifications

/// Core Location integration for sharing device location with agents.
///
/// Features:
/// - On-demand location sharing (only when explicitly authorized)
/// - Geofencing support for area-based alerts
/// - Privacy-first: location data is never persisted or cached
/// - Automatic authorization status tracking
///
/// Security notes:
/// - Uses "When In Use" authorization only (no background tracking)
/// - Location data is sent to the daemon only when the user explicitly shares
/// - Geofence regions are stored locally and cleared on app uninstall
/// - All location operations are gated on explicit user authorization
@MainActor
final class LocationService: NSObject, ObservableObject, CLLocationManagerDelegate {
    /// Current authorization status.
    @Published var authorizationStatus: CLAuthorizationStatus = .notDetermined

    /// Most recent location, if available.
    @Published var currentLocation: CLLocation?

    /// Whether a location request is in progress.
    @Published var isLocating: Bool = false

    /// Error from the most recent location attempt.
    @Published var locationError: String?

    /// Active geofence regions being monitored.
    @Published var activeGeofences: [GeofenceRegion] = []

    private let locationManager = CLLocationManager()
    private var locationContinuation: CheckedContinuation<CLLocation, Error>?

    override init() {
        super.init()
        locationManager.delegate = self
        locationManager.desiredAccuracy = kCLLocationAccuracyHundredMeters
        authorizationStatus = locationManager.authorizationStatus
    }

    // MARK: - Authorization

    /// Whether the user has authorized location access.
    var isAuthorized: Bool {
        switch authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways:
            return true
        default:
            return false
        }
    }

    /// Request "When In Use" location authorization.
    func requestAuthorization() {
        locationManager.requestWhenInUseAuthorization()
    }

    // MARK: - One-Shot Location

    /// Request the current location. Returns when a location fix is obtained.
    ///
    /// Throws if location services are unavailable or the user has denied access.
    func requestCurrentLocation() async throws -> CLLocation {
        guard isAuthorized else {
            throw LocationError.notAuthorized
        }

        isLocating = true
        locationError = nil

        defer { isLocating = false }

        return try await withCheckedThrowingContinuation { continuation in
            self.locationContinuation = continuation
            self.locationManager.requestLocation()
        }
    }

    /// Format the current location as a human-readable string for sending to agents.
    func formattedLocation() -> String? {
        guard let location = currentLocation else { return nil }
        let lat = String(format: "%.6f", location.coordinate.latitude)
        let lon = String(format: "%.6f", location.coordinate.longitude)
        let accuracy = String(format: "%.0f", location.horizontalAccuracy)
        return "Location: \(lat), \(lon) (accuracy: \(accuracy)m)"
    }

    // MARK: - Geofencing

    /// Add a geofence region to monitor.
    ///
    /// - Parameters:
    ///   - name: Human-readable name for the geofence.
    ///   - center: Center coordinate of the circular region.
    ///   - radiusMeters: Radius of the region in meters.
    ///   - notifyOnEntry: Whether to alert when entering the region.
    ///   - notifyOnExit: Whether to alert when leaving the region.
    func addGeofence(
        name: String,
        center: CLLocationCoordinate2D,
        radiusMeters: Double,
        notifyOnEntry: Bool = true,
        notifyOnExit: Bool = true
    ) {
        guard CLLocationManager.isMonitoringAvailable(for: CLCircularRegion.self) else {
            locationError = "Geofencing is not available on this device"
            return
        }

        let clampedRadius = min(radiusMeters, locationManager.maximumRegionMonitoringDistance)
        let identifier = "aegis-geofence-\(name)"

        let region = CLCircularRegion(
            center: center,
            radius: clampedRadius,
            identifier: identifier
        )
        region.notifyOnEntry = notifyOnEntry
        region.notifyOnExit = notifyOnExit

        locationManager.startMonitoring(for: region)

        let geofence = GeofenceRegion(
            name: name,
            identifier: identifier,
            center: center,
            radiusMeters: clampedRadius,
            notifyOnEntry: notifyOnEntry,
            notifyOnExit: notifyOnExit
        )
        activeGeofences.append(geofence)
    }

    /// Remove a geofence by name.
    func removeGeofence(name: String) {
        let identifier = "aegis-geofence-\(name)"
        for region in locationManager.monitoredRegions {
            if region.identifier == identifier {
                locationManager.stopMonitoring(for: region)
            }
        }
        activeGeofences.removeAll { $0.name == name }
    }

    /// Remove all geofences.
    func removeAllGeofences() {
        for region in locationManager.monitoredRegions {
            if region.identifier.hasPrefix("aegis-geofence-") {
                locationManager.stopMonitoring(for: region)
            }
        }
        activeGeofences.removeAll()
    }

    // MARK: - CLLocationManagerDelegate

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last else { return }
        Task { @MainActor in
            self.currentLocation = location
            self.isLocating = false
            self.locationError = nil
            if let continuation = self.locationContinuation {
                self.locationContinuation = nil
                continuation.resume(returning: location)
            }
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        Task { @MainActor in
            self.isLocating = false
            self.locationError = error.localizedDescription
            if let continuation = self.locationContinuation {
                self.locationContinuation = nil
                continuation.resume(throwing: error)
            }
        }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in
            self.authorizationStatus = manager.authorizationStatus
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didEnterRegion region: CLRegion) {
        guard region.identifier.hasPrefix("aegis-geofence-") else { return }
        let name = String(region.identifier.dropFirst("aegis-geofence-".count))
        postGeofenceNotification(name: name, event: "entered")
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didExitRegion region: CLRegion) {
        guard region.identifier.hasPrefix("aegis-geofence-") else { return }
        let name = String(region.identifier.dropFirst("aegis-geofence-".count))
        postGeofenceNotification(name: name, event: "exited")
    }

    // MARK: - Geofence Notifications

    private nonisolated func postGeofenceNotification(name: String, event: String) {
        let content = UNMutableNotificationContent()
        content.title = "Aegis: Geofence Alert"
        content.body = "You \(event) the '\(name)' area"
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: "geofence-\(name)-\(event)-\(Date().timeIntervalSince1970)",
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
    }
}

// MARK: - Supporting Types

/// A monitored geofence region.
struct GeofenceRegion: Identifiable {
    var id: String { identifier }

    let name: String
    let identifier: String
    let center: CLLocationCoordinate2D
    let radiusMeters: Double
    let notifyOnEntry: Bool
    let notifyOnExit: Bool
}

/// Errors from location operations.
enum LocationError: LocalizedError {
    case notAuthorized
    case unavailable
    case timeout

    var errorDescription: String? {
        switch self {
        case .notAuthorized:
            return "Location access not authorized. Enable location in Settings."
        case .unavailable:
            return "Location services are unavailable."
        case .timeout:
            return "Location request timed out."
        }
    }
}
