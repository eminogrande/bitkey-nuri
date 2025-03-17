import build.wallet.gradle.logic.extensions.allTargets

plugins {
  id("build.wallet.kmp")
  id("build.wallet.redacted")
  alias(libs.plugins.kotlin.serialization)
}

kotlin {
  allTargets()

  sourceSets {
    commonMain {
      dependencies {
        api(libs.kmp.kotlin.result)
        api(libs.kmp.kotlin.serialization.core)
        api(libs.kmp.kotlin.serialization.json)
        api(libs.kmp.ktor.client.content.negotiation)
        api(libs.kmp.ktor.client.core)
        api(libs.kmp.ktor.client.json)
        api(libs.kmp.ktor.client.logging)
        api(libs.kmp.okio)
        api(projects.libs.platformPublic)
        api(projects.libs.resultPublic)
        implementation(projects.libs.loggingPublic)
      }
    }

    commonTest {
      dependencies {
        implementation(projects.libs.ktorClientFake)
      }
    }

    val jvmTest by getting {
      dependencies {
        implementation(libs.jvm.ktor.client.okhttp)
      }
    }
    val androidUnitTest by getting {
      dependencies {
        implementation(libs.jvm.ktor.client.okhttp)
      }
    }
    val iosTest by getting {
      dependencies {
        implementation(libs.native.ktor.client.darwin)
      }
    }
  }
}
