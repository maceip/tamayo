plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.tamayo.mailproof.demo"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.tamayo.mailproof.demo"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"

        // Point these at your deployment. 10.0.2.2 reaches the host machine
        // from the Android emulator, matching the docker-compose quickstart.
        buildConfigField("String", "ISSUER_BASE", "\"http://10.0.2.2:8788\"")
        buildConfigField("String", "IMAGEHOST_BASE", "\"http://10.0.2.2:8789\"")
        buildConfigField("String", "IMAGEHOST_ORIGIN", "\"https://imagehost.local\"")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
}


dependencies {
    implementation(project(":enroll"))

    val composeBom = platform("androidx.compose:compose-bom:2026.05.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("com.squareup.okhttp3:okhttp:5.4.0")
}
