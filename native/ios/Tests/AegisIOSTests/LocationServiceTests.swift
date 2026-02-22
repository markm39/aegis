import XCTest
import CoreLocation
@testable import AegisIOS

final class LocationServiceTests: XCTestCase {

    // MARK: - Location Error Descriptions

    func testLocationErrorDescriptions() {
        let notAuth = LocationError.notAuthorized
        XCTAssertTrue(notAuth.localizedDescription.contains("not authorized"))

        let unavailable = LocationError.unavailable
        XCTAssertTrue(unavailable.localizedDescription.contains("unavailable"))

        let timeout = LocationError.timeout
        XCTAssertTrue(timeout.localizedDescription.contains("timed out"))
    }

    // MARK: - Geofence Region Model

    func testGeofenceRegionIdentifiable() {
        let region = GeofenceRegion(
            name: "office",
            identifier: "aegis-geofence-office",
            center: CLLocationCoordinate2D(latitude: 37.7749, longitude: -122.4194),
            radiusMeters: 200.0,
            notifyOnEntry: true,
            notifyOnExit: true
        )

        XCTAssertEqual(region.id, "aegis-geofence-office")
        XCTAssertEqual(region.name, "office")
        XCTAssertEqual(region.radiusMeters, 200.0, accuracy: 0.01)
        XCTAssertTrue(region.notifyOnEntry)
        XCTAssertTrue(region.notifyOnExit)
    }

    func testGeofenceRegionCoordinates() {
        let lat = 40.7128
        let lon = -74.0060

        let region = GeofenceRegion(
            name: "nyc",
            identifier: "aegis-geofence-nyc",
            center: CLLocationCoordinate2D(latitude: lat, longitude: lon),
            radiusMeters: 500.0,
            notifyOnEntry: true,
            notifyOnExit: false
        )

        XCTAssertEqual(region.center.latitude, lat, accuracy: 0.0001)
        XCTAssertEqual(region.center.longitude, lon, accuracy: 0.0001)
        XCTAssertFalse(region.notifyOnExit)
    }

    // MARK: - Location Formatting

    /// Test that the LocationService initializes without crashing.
    /// On simulators, location services may not be available.
    @MainActor
    func testLocationServiceInitialization() {
        let service = LocationService()
        XCTAssertNotNil(service)
        XCTAssertFalse(service.isLocating)
        XCTAssertNil(service.currentLocation)
        XCTAssertNil(service.locationError)
        XCTAssertTrue(service.activeGeofences.isEmpty)
    }

    @MainActor
    func testFormattedLocationNilWhenNoLocation() {
        let service = LocationService()
        XCTAssertNil(service.formattedLocation())
    }

    @MainActor
    func testIsAuthorizedDefault() {
        let service = LocationService()
        // On a fresh simulator, authorization is not determined
        // The service should report not authorized
        // (This may vary by test environment, so we just verify it does not crash)
        _ = service.isAuthorized
    }
}
