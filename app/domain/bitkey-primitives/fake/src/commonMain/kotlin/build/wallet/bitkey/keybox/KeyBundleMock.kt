package build.wallet.bitkey.keybox

import build.wallet.bitcoin.BitcoinNetworkType.SIGNET
import build.wallet.bitcoin.keys.DescriptorPublicKeyMock
import build.wallet.bitkey.app.AppKeyBundle
import build.wallet.bitkey.app.AppSpendingPublicKey
import build.wallet.bitkey.auth.AppGlobalAuthPublicKeyMock
import build.wallet.bitkey.auth.AppRecoveryAuthPublicKeyMock
import build.wallet.bitkey.auth.AppRecoveryAuthPublicKeyMock2
import build.wallet.bitkey.auth.HwAuthPublicKeyMock
import build.wallet.bitkey.hardware.HwKeyBundle
import build.wallet.bitkey.spending.AppSpendingPublicKeyMock
import build.wallet.bitkey.spending.HwSpendingPublicKeyMock
import build.wallet.crypto.PublicKey

val AppKeyBundleMock =
  AppKeyBundle(
    localId = "public-key-bundle-fake-id",
    networkType = SIGNET,
    spendingKey = AppSpendingPublicKeyMock,
    authKey = AppGlobalAuthPublicKeyMock,
    recoveryAuthKey = AppRecoveryAuthPublicKeyMock
  )

val AppKeyBundleMock2 =
  AppKeyBundle(
    localId = "public-key-bundle-fake-id-2",
    networkType = SIGNET,
    spendingKey = AppSpendingPublicKey(DescriptorPublicKeyMock(identifier = "spending-dpub-2")),
    authKey = PublicKey("app-dpub-2"),
    recoveryAuthKey = AppRecoveryAuthPublicKeyMock2
  )

val HwKeyBundleMock =
  HwKeyBundle(
    localId = "app-key-bundle-mock",
    networkType = SIGNET,
    spendingKey = HwSpendingPublicKeyMock,
    authKey = HwAuthPublicKeyMock
  )
