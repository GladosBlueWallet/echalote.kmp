import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = "io.bluewallet"
version = "0.0.1"

// Absolute path of src/commonTest/resources, baked into a generated test source so that
// every test target (JVM, Android host, Kotlin/Native) can read the offline fixtures.
val testFixtureDir: String =
    layout.projectDirectory
        .dir("src/commonTest/resources")
        .asFile.absolutePath
        .replace('\\', '/')
val generateTestFixtureDir by tasks.registering {
    val out = layout.buildDirectory.dir("generated/testFixtureDir/kotlin")
    val dir = testFixtureDir
    inputs.property("dir", dir)
    outputs.dir(out)
    doLast {
        val file = out.get().file("io/bluewallet/echalote/TestFixtureDir.kt").asFile
        file.parentFile.mkdirs()
        file.writeText(
            "package io.bluewallet.echalote\n\ninternal const val TEST_FIXTURE_DIR = \"$dir\"\n",
        )
    }
}

kotlin {
    jvm()
    androidLibrary {
        namespace = "io.bluewallet.echalote"
        compileSdk =
            libs.versions.android.compileSdk
                .get()
                .toInt()
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()

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
        commonTest {
            kotlin.srcDir(generateTestFixtureDir)
        }

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
