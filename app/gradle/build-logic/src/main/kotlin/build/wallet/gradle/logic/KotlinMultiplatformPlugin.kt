package build.wallet.gradle.logic

import build.wallet.gradle.dependencylocking.DependencyLockingCommonGroupConfigurationPlugin
import build.wallet.gradle.dependencylocking.DependencyLockingPlugin
import build.wallet.gradle.logic.gradle.apply
import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Apply this plugin using `build.wallet.kmp` ID on a library project that needs to
 * compile as a Kotlin multiplatform module
 */
internal class KotlinMultiplatformPlugin : Plugin<Project> {
  companion object {
    const val ID = "build.wallet.kmp"
  }

  override fun apply(target: Project) =
    target.run {
      pluginManager.apply("org.jetbrains.kotlin.multiplatform")
      pluginManager.apply<BasePlugin>()
      pluginManager.apply<DependencyLockingPlugin>()
      pluginManager.apply<DependencyLockingCommonGroupConfigurationPlugin>()
      pluginManager.apply<DependencyLockingDependencyConfigurationPlugin>()
      pluginManager.apply<AutomaticKotlinOptInPlugin>()
    }
}
