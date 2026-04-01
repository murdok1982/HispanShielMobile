package com.hispashield.dashboard.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun ProfileManagerScreen() {
    var autoRebootHours by remember { mutableStateOf(18) }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Aislamiento Multi-Perfil (Anti-Extorsión)", style = MaterialTheme.typography.headlineSmall)
        Spacer(modifier = Modifier.height(24.dp))
        
        Button(onClick = { /* Llama a profile-isolation-rs */ }, modifier = Modifier.fillMaxWidth()) {
            Text("Simular Evicción FBE de Caché (Purgar Claves Diarias)")
        }

        Spacer(modifier = Modifier.height(32.dp))
        
        Text("Protección de Evidencia (Auto-Reboot Pasivo)", style = MaterialTheme.typography.titleMedium)
        Card(modifier = Modifier.fillMaxWidth().padding(top = 16.dp)) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    "Temporizador de Auto-Reinicio al estado BFU (Expulsión FBE): $autoRebootHours Horas",
                    style = MaterialTheme.typography.bodyLarge
                )
                Slider(
                    value = autoRebootHours.toFloat(),
                    onValueChange = { autoRebootHours = it.toInt() },
                    valueRange = 1f..72f
                )
                Text(
                    "Si no introduces el PIN en las próximas $autoRebootHours h, el teléfono provocará un panic en su TrustZone forzando el descarte atómico de llaves y un reboot silente.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}
