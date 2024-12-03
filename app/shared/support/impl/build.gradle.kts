import build.wallet.gradle.logic.extensions.allTargets

plugins {
  id("build.wallet.kmp")
  alias(libs.plugins.kotlin.serialization)
}

kotlin {
  allTargets()

  sourceSets {
    commonMain {
      dependencies {
        implementation(projects.shared.f8eClientPublic)
        implementation(projects.shared.accountPublic)
        implementation(projects.shared.firmwarePublic)
      }
    }

    commonTest {
      dependencies {
        implementation(projects.shared.contactMethodFake)
        implementation(libs.kmp.test.kotest.framework.engine)
      }
    }

    val jvmIntegrationTest by getting {
      dependencies {
        implementation(projects.shared.integrationTestingPublic)
      }
    }
  }
}
