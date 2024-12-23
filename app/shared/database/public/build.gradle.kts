import build.wallet.gradle.dependencylocking.util.ifMatches
import build.wallet.gradle.logic.extensions.allTargets

plugins {
  id("build.wallet.kmp")
  id("build.wallet.di")
  id("build.wallet.sqldelight")
}

sqldelight {
  linkSqlite = false
  databases {
    create("BitkeyDatabase") {
      packageName.set("build.wallet.database.sqldelight")
      schemaOutputDirectory.set(File("src/commonMain/sqldelight/databases"))
      verifyMigrations.set(true)
      dialect(libs.kmp.sqldelight.sqlite.dialect)
    }
    create("BitkeyDebugDatabase") {
      packageName.set("build.wallet.database.sqldelight")
      schemaOutputDirectory.set(File("src/commonMain/sqldelightDebug/databases"))
      srcDirs.setFrom(File("src/commonMain/sqldelightDebug/"))
      verifyMigrations.set(true)
      dialect(libs.kmp.sqldelight.sqlite.dialect)
    }
  }
}

kotlin {
  allTargets()

  sourceSets {
    commonMain {
      dependencies {
        api(projects.shared.availabilityPublic)
        api(projects.shared.bitcoinPrimitivesPublic)
        api(projects.shared.bitkeyPrimitivesPublic)
        api(projects.shared.cloudBackupPublic)
        api(projects.shared.platformPublic)
        api(projects.shared.analyticsPublic)
        api(projects.shared.homePublic)
        api(projects.shared.sqldelightPublic)
        api(projects.shared.moneyPublic)
        api(projects.shared.onboardingPublic)
        api(projects.shared.partnershipsPublic)
        api(projects.shared.contactMethodPublic)
        api(projects.shared.fwupPublic)
        api(projects.shared.recoveryPublic)
        api(projects.shared.coachmarkPublic)
        api(libs.kmp.kotlin.datetime)
        implementation(projects.shared.loggingPublic)
        implementation(projects.shared.firmwarePublic)
        implementation(projects.shared.serializationPublic)
      }
    }

    commonTest {
      dependencies {
        implementation(projects.shared.bitcoinFake)
        implementation(projects.shared.bitkeyPrimitivesFake)
        implementation(projects.shared.bitcoinPrimitivesFake)
      }
    }

    val commonJvmTest by getting {
      resources.srcDir("${project.projectDir}/src/commonMain/sqldelight")
        .include("databases/*", "fixtures/*")

      dependencies {
        implementation(projects.shared.sqldelightTesting)
        implementation(libs.jvm.sqldelight.driver)
      }
    }
  }
}

customDependencyLocking {
  sqldelight.databases.configureEach {
    val databaseName = name

    configurations.configureEach {
      ifMatches {
        nameIs("${databaseName}DialectClasspath")
      } then {
        dependencyLockingGroup = dependencyLockingGroups.maybeCreate("SQLDelight-DialectClasspath")
      }

      ifMatches {
        nameIs("${databaseName}IntellijEnv", "${databaseName}MigrationEnv")
      } then {
        dependencyLockingGroup = dependencyLockingGroups.maybeCreate("SQLDelight-InternalClasspath")
      }
    }
  }
}
