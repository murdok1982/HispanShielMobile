package com.hispashield.dashboard

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.*
import com.hispashield.dashboard.ui.DashboardScreen
import com.hispashield.dashboard.ui.HardwareKillSwitchScreen
import com.hispashield.dashboard.ui.NetworkControlsScreen
import com.hispashield.dashboard.ui.ProfileManagerScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            HispaShieldTheme {
                MainAppHost()
            }
        }
    }
}

@Composable
fun MainAppHost() {
    val navController = rememberNavController()
    val navItems = listOf("dashboard", "network", "sensors", "profiles")

    Scaffold(
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route
                
                navItems.forEach { screen ->
                    NavigationBarItem(
                        selected = currentRoute == screen,
                        onClick = {
                            navController.navigate(screen) {
                                popUpTo(navController.graph.startDestinationId) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Text(screen.take(1).uppercase()) },
                        label = { Text(screen.capitalize()) }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = "dashboard",
            modifier = Modifier.padding(innerPadding)
        ) {
            composable("dashboard") { DashboardScreen() }
            composable("network") { NetworkControlsScreen() }
            composable("sensors") { HardwareKillSwitchScreen() }
            composable("profiles") { ProfileManagerScreen() }
        }
    }
}

@Composable
fun HispaShieldTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = androidx.compose.ui.graphics.Color(0xFF00FF88), // Verde Seguridad
            background = androidx.compose.ui.graphics.Color(0xFF121212),
            surface = androidx.compose.ui.graphics.Color(0xFF1E1E1E)
        ),
        content = content
    )
}
