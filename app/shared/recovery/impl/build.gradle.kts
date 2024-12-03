import build.wallet.gradle.logic.extensions.targets

plugins {
  id("build.wallet.kmp")
}

kotlin {
  targets(ios = true, jvm = true)

  sourceSets {
    commonMain {
      dependencies {
        api(projects.shared.databasePublic)
        api(projects.shared.debugPublic)
        api(projects.shared.f8eClientPublic)
        api(projects.shared.serializationPublic)
        implementation(projects.shared.queueProcessorPublic)
        implementation(projects.shared.relationshipsPublic)
      }
    }

    commonTest {
      dependencies {
        implementation(projects.shared.accountFake)
        implementation(projects.shared.bitcoinFake)
        implementation(projects.shared.debugFake)
        implementation(projects.shared.featureFlagFake)
        implementation(projects.shared.f8eClientFake)
        implementation(projects.shared.f8eClientImpl)
        implementation(projects.shared.keyboxFake)
        implementation(projects.shared.ktorClientFake)
        implementation(projects.shared.platformFake)
        implementation(projects.shared.recoveryFake)
        implementation(projects.shared.testingPublic)
        implementation(projects.shared.sqldelightTesting)
        implementation(projects.shared.f8eClientImpl)
        implementation(projects.shared.encryptionImpl)
        implementation(projects.shared.queueProcessorFake)
        implementation(projects.shared.encryptionFake)
        implementation(projects.shared.analyticsFake)
        implementation(projects.shared.relationshipsFake)
      }
    }

    val jvmIntegrationTest by getting {
      dependencies {
        implementation(projects.shared.accountFake)
        implementation(projects.shared.bitcoinFake)
        implementation(projects.shared.bitkeyPrimitivesFake)
        implementation(projects.shared.f8eClientFake)
        implementation(projects.shared.integrationTestingPublic)
        implementation(projects.shared.platformFake)
        implementation(projects.shared.recoveryFake)
        implementation(projects.shared.sqldelightTesting)
        implementation(projects.shared.testingPublic)
      }
    }
  }
}
