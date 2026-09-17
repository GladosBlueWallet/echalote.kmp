import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.extensions.DetektExtension
import org.gradle.api.file.FileTreeElement
import org.jlleitschuh.gradle.ktlint.KtlintExtension
import org.jlleitschuh.gradle.ktlint.tasks.BaseKtLintCheckTask

plugins {
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.vanniktech.mavenPublish) apply false
    alias(libs.plugins.ktlint)
    alias(libs.plugins.detekt) apply false
}

subprojects {
    apply(plugin = "org.jlleitschuh.gradle.ktlint")
    apply(plugin = "io.gitlab.arturbosch.detekt")
}

allprojects {
    pluginManager.withPlugin("org.jlleitschuh.gradle.ktlint") {
        extensions.configure<KtlintExtension> {
            filter {
                exclude("**/build/**")
                exclude("**/generated/**")
            }
        }
        tasks.withType<BaseKtLintCheckTask>().configureEach {
            exclude { element: FileTreeElement ->
                val path = element.file.absolutePath
                path.contains("/build/") || path.contains("/generated/")
            }
        }
    }
    pluginManager.withPlugin("io.gitlab.arturbosch.detekt") {
        extensions.configure<DetektExtension> {
            buildUponDefaultConfig = true
            config.setFrom(rootProject.file("config/detekt/detekt.yml"))
            baseline = rootProject.file("config/detekt/baselines/${project.name}.xml")
            source.setFrom(
                fileTree(projectDir) {
                    include("src/**/*.kt")
                    exclude("**/build/**")
                    exclude("**/generated/**")
                },
            )
        }
        tasks.withType<Detekt>().configureEach {
            jvmTarget = "11"
            exclude("**/build/**")
            exclude("**/generated/**")
        }
    }
}
