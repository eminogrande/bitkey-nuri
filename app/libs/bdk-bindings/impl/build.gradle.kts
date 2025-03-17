import build.wallet.gradle.logic.extensions.allTargets
import build.wallet.gradle.logic.gradle.exclude

plugins {
  id("build.wallet.kmp")
  id("build.wallet.di")
}

kotlin {
  allTargets()

  sourceSets {
    commonMain {
      dependencies {
        implementation(projects.libs.loggingPublic)
        implementation(projects.libs.stdlibPublic)
      }
    }

    commonTest {
      dependencies {
        implementation(projects.libs.bdkBindingsFake) {
          exclude(projects.libs.bdkBindingsPublic)
        }
      }
    }

    val jvmMain by getting {
      dependencies {
        implementation(libs.jvm.bdk)
      }
    }

    val androidMain by getting {
      dependencies {
        implementation(libs.android.bdk)
      }
    }
  }
}
