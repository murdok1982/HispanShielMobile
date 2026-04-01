plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.hispashield.dashboard"
    compileSdk = 34 // Android 14+ Target

    defaultConfig {
        applicationId = "com.hispashield.dashboard"
        minSdk = 33
        targetSdk = 34
        versionCode = 1
        versionName = "1.0-Fase3-Secure"
    }

    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.1"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.activity:activity-compose:1.8.2")
    
    // Compose BOM
    implementation(platform("androidx.compose:compose-bom:2024.01.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    
    // Compose Navigation para la BottomNavigationBar
    implementation("androidx.navigation:navigation-compose:2.7.6")
}
