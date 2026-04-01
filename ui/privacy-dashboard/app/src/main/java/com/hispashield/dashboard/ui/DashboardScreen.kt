package com.hispashield.dashboard.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun DashboardScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Centro de Comando", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(32.dp))
        
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Estado Actual: DEFENSIVO ESTRICTO", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onPrimaryContainer)
                Text("Cámaras: BLOQUEADAS", style = MaterialTheme.typography.bodyMedium)
                Text("Red (Fase 1): ZERO-TRUST (BPF ACTIVO)", style = MaterialTheme.typography.bodyMedium)
                Text("Módem IOMMU: PROTEGIDO (Split-Trust)", style = MaterialTheme.typography.bodyMedium)
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
        
        Text("Resumen GMS Sandbox Logs", style = MaterialTheme.typography.titleMedium)
        Text("3 Bloqueos silenciosos de rastreo publicitario detectados.", color = MaterialTheme.colorScheme.secondary)
    }
}
