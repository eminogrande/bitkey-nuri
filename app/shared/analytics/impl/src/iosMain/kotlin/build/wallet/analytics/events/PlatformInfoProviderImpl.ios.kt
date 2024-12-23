package build.wallet.analytics.events

import build.wallet.analytics.v1.Client.CLIENT_IOS_APP
import build.wallet.analytics.v1.OSType.OS_TYPE_IOS
import build.wallet.analytics.v1.PlatformInfo
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.platform.config.AppId
import build.wallet.platform.config.AppVersion
import build.wallet.platform.versions.OsVersionInfoProvider
import platform.UIKit.UIDevice

@BitkeyInject(AppScope::class)
class PlatformInfoProviderImpl(
  appId: AppId,
  appVersion: AppVersion,
  osVersionInfoProvider: OsVersionInfoProvider,
) : PlatformInfoProvider {
  private val platformInfoLazy by lazy {
    PlatformInfo(
      device_id = UIDevice.currentDevice.identifierForVendor?.UUIDString.orEmpty(),
      client_type = CLIENT_IOS_APP,
      application_version = appVersion.value,
      os_type = OS_TYPE_IOS,
      os_version = osVersionInfoProvider.getOsVersion(),
      device_make = "Apple",
      device_model = UIDevice.currentDevice.model,
      app_id = appId.value
    )
  }

  override fun getPlatformInfo(): PlatformInfo {
    return platformInfoLazy
  }
}
