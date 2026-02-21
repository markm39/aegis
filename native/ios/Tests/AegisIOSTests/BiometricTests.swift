import XCTest
@testable import AegisIOS

final class BiometricTests: XCTestCase {

    // MARK: - Biometric Availability Check

    /// Verify that canEvaluatePolicy does not crash regardless of device capabilities.
    /// On CI/simulators this will report biometrics as unavailable, which is expected.
    func test_biometric_availability_check() {
        let (available, typeName) = BiometricAuth.checkAvailability()

        // On a simulator or CI environment, biometrics are typically unavailable.
        // The important thing is that the call does not crash.
        XCTAssertNotNil(typeName, "Type name should never be nil")
        XCTAssertFalse(typeName.isEmpty, "Type name should not be empty")

        // The type should be one of the known types
        let knownTypes = ["Face ID", "Touch ID", "Optic ID", "Biometric"]
        XCTAssertTrue(knownTypes.contains(typeName),
                      "Biometric type '\(typeName)' should be a known type")

        // Log for informational purposes
        if available {
            print("[Test] Biometrics available: \(typeName)")
        } else {
            print("[Test] Biometrics not available (expected on simulator/CI)")
        }
    }

    /// Verify that the availability check returns consistent results across calls.
    func testBiometricAvailabilityIsConsistent() {
        let (available1, type1) = BiometricAuth.checkAvailability()
        let (available2, type2) = BiometricAuth.checkAvailability()

        XCTAssertEqual(available1, available2, "Availability should be consistent between calls")
        XCTAssertEqual(type1, type2, "Type should be consistent between calls")
    }
}
