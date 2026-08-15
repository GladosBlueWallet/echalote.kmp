import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = "org.bitcoin.kmp"
version = "0.0.1"

kotlin {
    jvm()
    androidLibrary {
        namespace = "org.hazae41.echalote"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        withJava()
        withHostTestBuilder {}.configure {}
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }

        compilerOptions {
            jvmTarget = JvmTarget.JVM_11
        }
    }
    iosArm64()
    iosSimulatorArm64()
    linuxX64()

    sourceSets {
        commonMain.dependencies {
            implementation(libs.kotlinx.coroutines.core)
        }

        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.kotlinx.coroutines.test)
            implementation(libs.kotlinx.serialization.json)
        }
    }
}

mavenPublishing {
    publishToMavenCentral()

    signAllPublications()

    coordinates(group.toString(), "echalote", version.toString())

    pom {
        name = "echalote"
        description = "Kotlin Multiplatform Tor client protocol (port of @hazae41/echalote)"
        inceptionYear = "2026"
        url = "https://github.com/GladosBlueWallet/echalote.kmp/"
        licenses {
            license {
                name = "MIT License"
                url = "https://opensource.org/licenses/MIT"
                distribution = "https://opensource.org/licenses/MIT"
            }
        }
        developers {
            developer {
                id = "overtorment"
                name = "Overtorment"
                url = "https://github.com/Overtorment/"
            }
        }
        scm {
            url = "https://github.com/GladosBlueWallet/echalote.kmp/"
            connection = "scm:git:git://github.com/GladosBlueWallet/echalote.kmp.git"
            developerConnection = "scm:git:ssh://git@github.com/GladosBlueWallet/echalote.kmp.git"
        }
    }
}
