package com.aegis.android

import com.aegis.android.api.LocationData
import com.aegis.android.services.extractJsonField
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for location handling logic.
 *
 * Tests LocationData model construction, serialization, JSON field extraction,
 * and edge cases. Android-specific location API tests require instrumentation.
 */
class LocationServiceTest {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = false
    }

    // -- LocationData Construction --

    @Test
    fun test_location_data_with_all_fields() {
        val location = LocationData(
            latitude = 37.7749,
            longitude = -122.4194,
            accuracy = 10.0f,
            altitude = 15.0,
            timestamp = 1700000000000L,
        )
        assertEquals(37.7749, location.latitude, 0.0001)
        assertEquals(-122.4194, location.longitude, 0.0001)
        assertEquals(10.0f, location.accuracy!!, 0.01f)
        assertEquals(15.0, location.altitude!!, 0.01)
        assertEquals(1700000000000L, location.timestamp)
    }

    @Test
    fun test_location_data_without_optional_fields() {
        val location = LocationData(
            latitude = 0.0,
            longitude = 0.0,
        )
        assertNull(location.accuracy)
        assertNull(location.altitude)
        assertTrue(location.timestamp > 0)
    }

    @Test
    fun test_location_data_extreme_coordinates() {
        // North pole
        val north = LocationData(latitude = 90.0, longitude = 0.0)
        assertEquals(90.0, north.latitude, 0.0)

        // South pole
        val south = LocationData(latitude = -90.0, longitude = 0.0)
        assertEquals(-90.0, south.latitude, 0.0)

        // Date line
        val east = LocationData(latitude = 0.0, longitude = 180.0)
        assertEquals(180.0, east.longitude, 0.0)

        val west = LocationData(latitude = 0.0, longitude = -180.0)
        assertEquals(-180.0, west.longitude, 0.0)
    }

    // -- LocationData Serialization --

    @Test
    fun test_location_data_round_trip() {
        val original = LocationData(
            latitude = 37.7749,
            longitude = -122.4194,
            accuracy = 5.0f,
            altitude = 100.0,
            timestamp = 1700000000000L,
        )
        val serialized = json.encodeToString(LocationData.serializer(), original)
        val deserialized = json.decodeFromString<LocationData>(serialized)

        assertEquals(original.latitude, deserialized.latitude, 0.0001)
        assertEquals(original.longitude, deserialized.longitude, 0.0001)
        assertEquals(original.accuracy, deserialized.accuracy)
        assertEquals(original.altitude, deserialized.altitude)
        assertEquals(original.timestamp, deserialized.timestamp)
    }

    @Test
    fun test_location_data_json_fields() {
        val location = LocationData(
            latitude = 51.5074,
            longitude = -0.1278,
            accuracy = 3.0f,
        )
        val serialized = json.encodeToString(LocationData.serializer(), location)
        assertTrue(serialized.contains("\"latitude\""))
        assertTrue(serialized.contains("\"longitude\""))
        assertTrue(serialized.contains("\"accuracy\""))
        assertTrue(serialized.contains("51.5074"))
        assertTrue(serialized.contains("-0.1278"))
    }

    // -- JSON Field Extraction (used by ConnectionService) --

    @Test
    fun test_extract_json_field_simple() {
        val jsonStr = """{"agent_name": "claude-1", "request_id": "req-123"}"""
        assertEquals("claude-1", extractJsonField(jsonStr, "agent_name"))
        assertEquals("req-123", extractJsonField(jsonStr, "request_id"))
    }

    @Test
    fun test_extract_json_field_missing() {
        val jsonStr = """{"agent_name": "claude-1"}"""
        assertNull(extractJsonField(jsonStr, "request_id"))
    }

    @Test
    fun test_extract_json_field_empty_json() {
        assertNull(extractJsonField("{}", "agent_name"))
    }

    @Test
    fun test_extract_json_field_nested_value() {
        val jsonStr = """{"type": "pending_request", "data": {"agent_name": "test-agent"}}"""
        assertEquals("test-agent", extractJsonField(jsonStr, "agent_name"))
    }

    @Test
    fun test_extract_json_field_with_spaces() {
        val jsonStr = """{"agent_name" : "spaced-agent" , "request_id" : "req-456"}"""
        assertEquals("spaced-agent", extractJsonField(jsonStr, "agent_name"))
        assertEquals("req-456", extractJsonField(jsonStr, "request_id"))
    }

    // -- Coordinate Validation Helpers --

    @Test
    fun test_valid_latitude_range() {
        assertTrue(isValidLatitude(0.0))
        assertTrue(isValidLatitude(90.0))
        assertTrue(isValidLatitude(-90.0))
        assertTrue(isValidLatitude(37.7749))
        assertFalse(isValidLatitude(91.0))
        assertFalse(isValidLatitude(-91.0))
    }

    @Test
    fun test_valid_longitude_range() {
        assertTrue(isValidLongitude(0.0))
        assertTrue(isValidLongitude(180.0))
        assertTrue(isValidLongitude(-180.0))
        assertTrue(isValidLongitude(-122.4194))
        assertFalse(isValidLongitude(181.0))
        assertFalse(isValidLongitude(-181.0))
    }

    // Helper functions for coordinate validation (mirrors what the service would use)
    private fun isValidLatitude(lat: Double): Boolean = lat in -90.0..90.0
    private fun isValidLongitude(lon: Double): Boolean = lon in -180.0..180.0
    private fun assertFalse(condition: Boolean) = org.junit.Assert.assertFalse(condition)
}
