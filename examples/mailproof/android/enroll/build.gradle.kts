plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.tamayo.enroll"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}


dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.05.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    implementation("com.squareup.okhttp3:okhttp:5.4.0")
    // Pure-Java Ed25519 for the holder proof-of-possession key.
    implementation("net.i2p.crypto:eddsa:0.3.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.4.0")
    // Real org.json for host-side unit tests (android.jar ships stubs only).
    testImplementation("org.json:json:20240303")
}
