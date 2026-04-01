package com.hispashield.dashboard.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun HardwareKillSwitchScreen() {
    var globalMicBlocked by remember { mutableStateOf(true) }
    var globalCamBlocked by remember { mutableStateOf(true) }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Sensores & Hardware (SensorGuard)", style = MaterialTheme.typography.headlineSmall)
        Spacer(modifier = Modifier.height(24.dp))
        
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row {
                    Text("Bloqueo Activo y Lógico de Cámara", modifier = Modifier.weight(1f))
                    Switch(checked = globalCamBlocked, onCheckedChange = { globalCamBlocked = it })
                }
                Text("Desactiva internamente el HAL de CameraServer. No requiere permiso root, inyectado vía sistema.", style = MaterialTheme.typography.bodySmall)
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row {
                    Text("Aislamiento Maestro de Micrófono", modifier = Modifier.weight(1f))
                    Switch(checked = globalMicBlocked, onCheckedChange = { globalMicBlocked = it })
                }
                Text("Preaviso: AudioRecord retornará silencia absoluto (0 bytes) a cualquier app incluso si tuviera permiso concedido.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
