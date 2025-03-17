import build.wallet.gradle.logic.extensions.targets

plugins {
  id("build.wallet.kmp")
  alias(libs.plugins.kotlin.serialization)
}

kotlin {
  targets(ios = true, jvm = true)

  sourceSets {
    commonMain {
      dependencies {
        implementation(libs.kmp.kotlin.serialization.core)
        implementation(libs.kmp.kotlin.serialization.json)
        implementation(projects.domain.featureFlagPublic)
        implementation(projects.domain.firmwarePublic)
        implementation(projects.shared.workerPublic)
      }
    }
  }
}
