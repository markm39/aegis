package com.aegis.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.aegis.android.api.DaemonClient
import com.aegis.android.security.TokenStore
import com.aegis.android.services.ConnectionService
import kotlinx.coroutines.launch

/**
 * Settings view for configuring the daemon connection, authentication, and app preferences.
 *
 * Sections:
 * - Server URL: validated text field (HTTPS required, localhost exception)
 * - API Token: password field stored in EncryptedSharedPreferences
 * - Connection: test button with status indicator
 * - Background Service: toggle for persistent WebSocket connection
 * - Security: biometric authentication toggle
 * - Notifications: approval notification toggle
 * - About: app version
 *
 * Security:
 * - API token is stored exclusively in EncryptedSharedPreferences (Android Keystore-backed)
 * - Server URL is validated before saving (HTTPS required for remote servers)
 * - Token input is masked using PasswordVisualTransformation
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tokenStore = remember { TokenStore(context) }

    // Server URL state
    var serverUrl by remember { mutableStateOf(tokenStore.getServerUrl()) }
    var urlValidationError by remember { mutableStateOf<String?>(null) }

    // Token state
    var tokenInput by remember { mutableStateOf("") }
    var hasToken by remember { mutableStateOf(tokenStore.hasToken()) }

    // Connection test state
    var isTesting by remember { mutableStateOf(false) }
    var testResult by remember { mutableStateOf<ConnectionTestResult?>(null) }

    // Preferences
    var biometricEnabled by remember { mutableStateOf(tokenStore.isBiometricEnabled()) }
    var notificationsEnabled by remember { mutableStateOf(tokenStore.isNotificationsEnabled()) }
    var backgroundServiceEnabled by remember { mutableStateOf(tokenStore.isBackgroundServiceEnabled()) }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Settings") })
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // -- Server Section --
            SectionCard(title = "Server") {
                OutlinedTextField(
                    value = serverUrl,
                    onValueChange = { value ->
                        serverUrl = value
                        urlValidationError = validateUrl(value)
                    },
                    label = { Text("Server URL") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    isError = urlValidationError != null,
                    supportingText = {
                        if (urlValidationError != null) {
                            Text(
                                text = urlValidationError!!,
                                color = MaterialTheme.colorScheme.error,
                            )
                        } else {
                            Text("HTTPS is required for remote servers. HTTP is only allowed for localhost.")
                        }
                    },
                )

                Spacer(modifier = Modifier.height(8.dp))

                Button(
                    onClick = {
                        if (DaemonClient.isValidServerUrl(serverUrl)) {
                            tokenStore.saveServerUrl(serverUrl)
                            urlValidationError = null
                        }
                    },
                    enabled = urlValidationError == null && serverUrl.isNotBlank(),
                ) {
                    Text("Save URL")
                }
            }

            // -- Authentication Section --
            SectionCard(title = "Authentication") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = tokenInput,
                        onValueChange = { tokenInput = it },
                        label = { Text("API Token") },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                    )
                    if (hasToken) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = "Token stored",
                            tint = Color(0xFF4CAF50),
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(
                        onClick = {
                            val trimmed = tokenInput.trim()
                            if (tokenStore.saveToken(trimmed)) {
                                hasToken = true
                                tokenInput = ""
                            }
                        },
                        enabled = tokenInput.isNotBlank(),
                    ) {
                        Text("Save Token")
                    }

                    if (hasToken) {
                        OutlinedButton(
                            onClick = {
                                tokenStore.deleteToken()
                                hasToken = false
                                tokenInput = ""
                            },
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error,
                            ),
                        ) {
                            Text("Remove Token")
                        }
                    }
                }

                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "The API token is stored securely using Android Keystore encryption. It is never written to disk in plaintext.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // -- Connection Section --
            SectionCard(title = "Connection") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    if (isTesting) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Testing...", style = MaterialTheme.typography.bodyMedium)
                        }
                    } else {
                        testResult?.let { result ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = if (result.success) Icons.Default.CheckCircle else Icons.Default.Error,
                                    contentDescription = null,
                                    tint = if (result.success) Color(0xFF4CAF50) else Color(0xFFF44336),
                                    modifier = Modifier.size(16.dp),
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = result.message,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (result.success) Color(0xFF4CAF50) else Color(0xFFF44336),
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Button(
                    onClick = {
                        isTesting = true
                        testResult = null
                        scope.launch {
                            val client = DaemonClient(tokenStore.getServerUrl(), tokenStore)
                            val error = client.testConnection()
                            testResult = if (error == null) {
                                ConnectionTestResult(true, "Connection successful")
                            } else {
                                ConnectionTestResult(false, error)
                            }
                            isTesting = false
                        }
                    },
                    enabled = !isTesting,
                ) {
                    Text("Test Connection")
                }
            }

            // -- Background Service Section --
            SectionCard(title = "Background Service") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Persistent Connection",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            text = "Keep a WebSocket connection to the daemon for real-time updates and push notifications",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = backgroundServiceEnabled,
                        onCheckedChange = { enabled ->
                            backgroundServiceEnabled = enabled
                            tokenStore.setBackgroundServiceEnabled(enabled)
                            if (enabled) {
                                ConnectionService.start(context)
                            } else {
                                ConnectionService.stop(context)
                            }
                        },
                    )
                }
            }

            // -- Security Section --
            SectionCard(title = "Security") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Require Biometric",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            text = "Authenticate with fingerprint or face to access Aegis",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = biometricEnabled,
                        onCheckedChange = { enabled ->
                            biometricEnabled = enabled
                            tokenStore.setBiometricEnabled(enabled)
                        },
                    )
                }
            }

            // -- Notifications Section --
            SectionCard(title = "Notifications") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Approval Notifications",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            text = "Receive notifications when agents request approval for actions",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = notificationsEnabled,
                        onCheckedChange = { enabled ->
                            notificationsEnabled = enabled
                            tokenStore.setNotificationsEnabled(enabled)
                        },
                    )
                }
            }

            // -- About Section --
            SectionCard(title = "About") {
                InfoRow("Version", "0.1.0")
                InfoRow("Build", "1")
            }
        }
    }
}

@Composable
private fun SectionCard(
    title: String,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(modifier = Modifier.height(12.dp))
            content()
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun validateUrl(url: String): String? {
    if (url.isBlank()) return null
    return if (DaemonClient.isValidServerUrl(url)) {
        null
    } else {
        "Invalid URL. Use https:// for remote servers, or http://localhost for development."
    }
}

private data class ConnectionTestResult(
    val success: Boolean,
    val message: String,
)
