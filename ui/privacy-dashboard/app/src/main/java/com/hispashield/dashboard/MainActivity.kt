package com.hispashield.dashboard

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            HispaShieldTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    PrivacyDashboard()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PrivacyDashboard() {
    var globalMicBlocked by remember { mutableStateOf(true) }
    var globalCamBlocked by remember { mutableStateOf(true) }
    var strictNetwork by remember { mutableStateOf(true) }
    var autoRebootHours by remember { mutableStateOf(18) }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Centro de Privacidad - HispaShield") }) }
    ) { padding ->
        Column(modifier = Modifier.padding(padding).padding(16.dp)) {
            Text("Bloqueos de Hardware (SensorGuard)", style = MaterialTheme.typography.titleMedium)
            
            Row {
                Text("Cámara (Cortacorriente lógico)", modifier = Modifier.weight(1f))
                Switch(checked = globalCamBlocked, onCheckedChange = { globalCamBlocked = it })
            }
            Row {
                Text("Micrófono (Cortacorriente lógico)", modifier = Modifier.weight(1f))
                Switch(checked = globalMicBlocked, onCheckedChange = { globalMicBlocked = it })
            }

            Spacer(modifier = Modifier.height(24.dp))
            Text("Políticas de Red y Aislamiento", style = MaterialTheme.typography.titleMedium)
            
            Row {
                Text("Default-Deny en nuevas apps (BPF)", modifier = Modifier.weight(1f))
                Switch(checked = strictNetwork, onCheckedChange = { strictNetwork = it })
            }

            Spacer(modifier = Modifier.height(24.dp))
            Text("Protección de Evidencia (Defensiva)", style = MaterialTheme.typography.titleMedium)
            
            Text("Temporizador de Auto-Reinicio (Expulsión FBE): $autoRebootHours Horas")
            Slider(
                value = autoRebootHours.toFloat(),
                onValueChange = { autoRebootHours = it.toInt() },
                valueRange = 1f..72f
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                "Info: El Auto-reinicio es una medida pasiva certificada para forzar el estado " +
                "BFU (Before First Unlock) ante el hurto del dispositivo, cifrando los datos " +
                "sin requerir interacción o manipulación forense destructiva.", 
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.secondary
            )
        }
    }
}

// Stub for theme component
@Composable
fun HispaShieldTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = darkColorScheme(), content = content)
}
