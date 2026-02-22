package com.aegis.android.ui

import android.Manifest
import android.content.pm.PackageManager
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.aegis.android.api.DaemonClient
import com.aegis.android.api.PairingInfo
import com.aegis.android.security.TokenStore
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import java.util.concurrent.Executors

/**
 * Pairing flow for connecting the app to an Aegis daemon.
 *
 * Supports two pairing methods:
 * 1. QR code scanning (CameraX + ML Kit barcode scanner)
 * 2. Manual code entry (server URL + API token)
 *
 * After pairing, the connection info is stored securely in EncryptedSharedPreferences.
 * The flow includes connection testing and auto-reconnect guidance.
 */

private enum class PairingStep {
    METHOD_SELECT,
    QR_SCAN,
    MANUAL_ENTRY,
    CONNECTING,
    SUCCESS,
    FAILURE,
}

@kotlin.OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairingScreen(
    onBack: () -> Unit,
    onPaired: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tokenStore = remember { TokenStore(context) }

    var step by remember { mutableStateOf(PairingStep.METHOD_SELECT) }
    var serverUrl by remember { mutableStateOf("") }
    var token by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }

    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
        if (granted) {
            step = PairingStep.QR_SCAN
        }
    }

    fun attemptConnection() {
        step = PairingStep.CONNECTING
        errorMessage = null

        scope.launch {
            try {
                if (!DaemonClient.isValidServerUrl(serverUrl)) {
                    errorMessage = "Invalid server URL. Use https:// for remote servers, or http://localhost for development."
                    step = PairingStep.FAILURE
                    return@launch
                }

                if (!TokenStore.isValidFormat(token)) {
                    errorMessage = "Invalid token format. Token must be at least ${TokenStore.MINIMUM_TOKEN_LENGTH} characters with no whitespace."
                    step = PairingStep.FAILURE
                    return@launch
                }

                // Save credentials
                tokenStore.saveServerUrl(serverUrl)
                tokenStore.saveToken(token)

                // Test connection
                val client = DaemonClient(serverUrl, tokenStore)
                val testError = client.testConnection()
                if (testError != null) {
                    errorMessage = testError
                    step = PairingStep.FAILURE
                } else {
                    step = PairingStep.SUCCESS
                }
            } catch (e: Exception) {
                errorMessage = DaemonClient.friendlyError(e)
                step = PairingStep.FAILURE
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when (step) {
                            PairingStep.METHOD_SELECT -> "Pair Device"
                            PairingStep.QR_SCAN -> "Scan QR Code"
                            PairingStep.MANUAL_ENTRY -> "Manual Entry"
                            PairingStep.CONNECTING -> "Connecting..."
                            PairingStep.SUCCESS -> "Paired"
                            PairingStep.FAILURE -> "Connection Failed"
                        }
                    )
                },
                navigationIcon = {
                    IconButton(onClick = {
                        when (step) {
                            PairingStep.METHOD_SELECT -> onBack()
                            PairingStep.QR_SCAN,
                            PairingStep.MANUAL_ENTRY -> step = PairingStep.METHOD_SELECT
                            PairingStep.FAILURE -> step = PairingStep.METHOD_SELECT
                            PairingStep.SUCCESS -> onPaired()
                            PairingStep.CONNECTING -> {} // no-op during connection
                        }
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            when (step) {
                PairingStep.METHOD_SELECT -> MethodSelectView(
                    onScanQr = {
                        if (hasCameraPermission) {
                            step = PairingStep.QR_SCAN
                        } else {
                            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                        }
                    },
                    onManualEntry = { step = PairingStep.MANUAL_ENTRY },
                )

                PairingStep.QR_SCAN -> QrScanView(
                    onScanned = { pairingInfo ->
                        serverUrl = pairingInfo.serverUrl
                        token = pairingInfo.token
                        attemptConnection()
                    },
                    onError = { error ->
                        errorMessage = error
                        step = PairingStep.FAILURE
                    },
                )

                PairingStep.MANUAL_ENTRY -> ManualEntryView(
                    serverUrl = serverUrl,
                    onServerUrlChange = { serverUrl = it },
                    token = token,
                    onTokenChange = { token = it },
                    onConnect = { attemptConnection() },
                )

                PairingStep.CONNECTING -> ConnectingView()

                PairingStep.SUCCESS -> SuccessView(
                    serverUrl = serverUrl,
                    onContinue = onPaired,
                )

                PairingStep.FAILURE -> FailureView(
                    errorMessage = errorMessage ?: "Unknown error",
                    onRetry = {
                        step = PairingStep.METHOD_SELECT
                        errorMessage = null
                    },
                )
            }
        }
    }
}

@Composable
private fun MethodSelectView(
    onScanQr: () -> Unit,
    onManualEntry: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Default.QrCodeScanner,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = MaterialTheme.colorScheme.primary,
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Connect to Aegis",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Pair this device with your Aegis daemon to monitor and control your agent fleet remotely.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )

        Spacer(modifier = Modifier.height(40.dp))

        Button(
            onClick = onScanQr,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Scan QR Code")
        }

        Spacer(modifier = Modifier.height(12.dp))

        OutlinedButton(
            onClick = onManualEntry,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Enter Manually")
        }

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Run 'aegis pair' on your server to generate a QR code or pairing token.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

@OptIn(ExperimentalGetImage::class)
@Composable
private fun QrScanView(
    onScanned: (PairingInfo) -> Unit,
    onError: (String) -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var scanned by remember { mutableStateOf(false) }

    val json = remember {
        Json { ignoreUnknownKeys = true; isLenient = true }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        AndroidView(
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                val executor = Executors.newSingleThreadExecutor()

                cameraProviderFuture.addListener({
                    val cameraProvider = cameraProviderFuture.get()
                    val preview = Preview.Builder().build().also {
                        it.surfaceProvider = previewView.surfaceProvider
                    }

                    val imageAnalysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()

                    val barcodeScanner = BarcodeScanning.getClient()

                    imageAnalysis.setAnalyzer(executor) { imageProxy ->
                        val mediaImage = imageProxy.image
                        if (mediaImage != null && !scanned) {
                            val inputImage = InputImage.fromMediaImage(
                                mediaImage,
                                imageProxy.imageInfo.rotationDegrees,
                            )
                            barcodeScanner.process(inputImage)
                                .addOnSuccessListener { barcodes ->
                                    for (barcode in barcodes) {
                                        if (barcode.valueType == Barcode.TYPE_TEXT && !scanned) {
                                            val rawValue = barcode.rawValue ?: continue
                                            scanned = true
                                            try {
                                                val pairingInfo = json.decodeFromString<PairingInfo>(rawValue)
                                                onScanned(pairingInfo)
                                            } catch (e: Exception) {
                                                // Try parsing as URL+token format: "url|token"
                                                val parts = rawValue.split("|", limit = 2)
                                                if (parts.size == 2) {
                                                    onScanned(PairingInfo(
                                                        serverUrl = parts[0].trim(),
                                                        token = parts[1].trim(),
                                                    ))
                                                } else {
                                                    scanned = false
                                                    onError("Invalid QR code format. Expected JSON with server_url and token fields.")
                                                }
                                            }
                                        }
                                    }
                                }
                                .addOnCompleteListener {
                                    imageProxy.close()
                                }
                        } else {
                            imageProxy.close()
                        }
                    }

                    try {
                        cameraProvider.unbindAll()
                        cameraProvider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_BACK_CAMERA,
                            preview,
                            imageAnalysis,
                        )
                    } catch (e: Exception) {
                        Log.e("PairingScreen", "Camera bind failed", e)
                        onError("Failed to start camera: ${e.message}")
                    }
                }, ContextCompat.getMainExecutor(ctx))

                previewView
            },
            modifier = Modifier.fillMaxSize(),
        )

        // Scan overlay
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Box(
                modifier = Modifier
                    .size(250.dp)
                    .border(
                        width = 3.dp,
                        color = MaterialTheme.colorScheme.primary,
                        shape = RoundedCornerShape(16.dp),
                    ),
            )
        }

        // Instructions
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.BottomCenter)
                .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.9f))
                .padding(24.dp),
        ) {
            Text(
                text = "Point your camera at the QR code displayed by 'aegis pair'",
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun ManualEntryView(
    serverUrl: String,
    onServerUrlChange: (String) -> Unit,
    token: String,
    onTokenChange: (String) -> Unit,
    onConnect: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Enter Connection Details",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )

        Text(
            text = "Enter the server URL and API token from your Aegis daemon configuration.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        OutlinedTextField(
            value = serverUrl,
            onValueChange = onServerUrlChange,
            label = { Text("Server URL") },
            placeholder = { Text("https://aegis.example.com:3100") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            supportingText = {
                Text("HTTPS required for remote servers. HTTP allowed for localhost.")
            },
        )

        OutlinedTextField(
            value = token,
            onValueChange = onTokenChange,
            label = { Text("API Token") },
            placeholder = { Text("Your daemon API token") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            supportingText = {
                Text("Minimum ${TokenStore.MINIMUM_TOKEN_LENGTH} characters. Stored securely with Android Keystore encryption.")
            },
        )

        Spacer(modifier = Modifier.height(8.dp))

        Button(
            onClick = onConnect,
            modifier = Modifier.fillMaxWidth(),
            enabled = serverUrl.isNotBlank() && token.isNotBlank(),
        ) {
            Text("Connect")
        }
    }
}

@Composable
private fun ConnectingView() {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        CircularProgressIndicator(modifier = Modifier.size(48.dp))
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "Connecting to daemon...",
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Testing the connection and verifying credentials.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun SuccessView(
    serverUrl: String,
    onContinue: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Default.CheckCircle,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = Color(0xFF4CAF50),
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "Connected",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Successfully paired with:",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = serverUrl,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "The app will automatically reconnect if the connection is lost.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(32.dp))
        Button(
            onClick = onContinue,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Continue to Dashboard")
        }
    }
}

@Composable
private fun FailureView(
    errorMessage: String,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Default.Error,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = MaterialTheme.colorScheme.error,
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "Connection Failed",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
            ),
        ) {
            Text(
                text = errorMessage,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.padding(16.dp),
            )
        }
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "Check that the daemon is running and the URL and token are correct.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(
            onClick = onRetry,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Try Again")
        }
    }
}
