package build.wallet.gradle.logic

import build.wallet.gradle.dependencylocking.DependencyLockingCommonGroupConfigurationPlugin
import build.wallet.gradle.dependencylocking.DependencyLockingPlugin
import build.wallet.gradle.logic.gradle.apply
import com.android.build.gradle.internal.tasks.CompileArtProfileTask
import com.android.build.gradle.internal.tasks.MergeArtProfileTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.withType

/**
 * Apply this plugin using `build.wallet.android.app` ID on an Android application project that
 * needs to compile Kotlin.
 */
internal class AndroidAppPlugin : Plugin<Project> {
  override fun apply(target: Project) =
    target.run {
      pluginManager.apply("com.android.application")
      pluginManager.apply<BasePlugin>()
      pluginManager.apply<KotlinBasePlugin>()
      pluginManager.apply<DependencyLockingPlugin>()
      pluginManager.apply<DependencyLockingCommonGroupConfigurationPlugin>()
      pluginManager.apply<DependencyLockingDependencyConfigurationPlugin>()
      pluginManager.apply<AutomaticKotlinOptInPlugin>()

      android {
        commonConfiguration(project)

        tasks.withType<CompileArtProfileTask>().configureEach {
          enabled = false
        }

        tasks.withType<MergeArtProfileTask>().configureEach {
          enabled = false
        }
      }
    }
}
