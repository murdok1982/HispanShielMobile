package com.hispashield.dashboard.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun NetworkControlsScreen() {
    var globalFirewall by remember { mutableStateOf(true) }
    var allowLocalDns by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Políticas Strict MAC & Red (NetworkPolicy Daemon)", style = MaterialTheme.typography.headlineSmall)
        Spacer(modifier = Modifier.height(24.dp))
        
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row {
                    Text("Bloqueo Default-Deny Global (BPF)", modifier = Modifier.weight(1f))
                    Switch(checked = globalFirewall, onCheckedChange = { globalFirewall = it })
                }
                Text("Todas las apps nuevas no tendrán enrutamiento saliente hasta una aprobación manual.", style = MaterialTheme.typography.bodySmall)
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row {
                    Text("Forzar Randomización MAC por Sesión", modifier = Modifier.weight(1f))
                    Switch(checked = true, onCheckedChange = { }) // Forzado activado
                }
                Text("Modo Anti-Tracking activo permanentemente a nivel del driver WLAN.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
