package build.wallet.di

import build.wallet.bdk.bindings.*
import build.wallet.bitcoin.descriptor.FrostWalletDescriptorFactory
import build.wallet.crypto.Spake2
import build.wallet.crypto.WsmVerifier
import build.wallet.datadog.DatadogRumMonitor
import build.wallet.datadog.DatadogTracer
import build.wallet.encrypt.*
import build.wallet.firmware.FirmwareCommsLogBuffer
import build.wallet.firmware.HardwareAttestation
import build.wallet.firmware.Teltra
import build.wallet.frost.ShareGeneratorFactory
import build.wallet.logging.LogWriterContextStore
import build.wallet.logging.dev.LogStoreInMemoryImpl
import build.wallet.logging.prod.BoundedInMemoryLogStoreImpl
import build.wallet.phonenumber.lib.PhoneNumberLibBindings
import build.wallet.platform.PlatformContext
import build.wallet.platform.biometrics.BiometricPrompter
import build.wallet.platform.config.*
import build.wallet.platform.data.FileDirectoryProvider
import build.wallet.platform.data.FileDirectoryProviderImpl
import build.wallet.platform.data.FileManager
import build.wallet.sqldelight.DatabaseIntegrityCheckerImpl
import build.wallet.time.Delayer
import co.touchlab.kermit.LogWriter
import platform.Foundation.NSBundle

@Suppress("unused") // Used in AppContext.swift
fun makeAppComponent(
  appVariant: AppVariant,
  bdkAddressBuilder: BdkAddressBuilder,
  bdkBlockchainFactory: BdkBlockchainFactory,
  bdkBumpFeeTxBuilderFactory: BdkBumpFeeTxBuilderFactory,
  bdkDescriptorSecretKeyGenerator: BdkDescriptorSecretKeyGenerator,
  bdkMnemonicGenerator: BdkMnemonicGenerator,
  bdkPartiallySignedTransactionBuilder: BdkPartiallySignedTransactionBuilder,
  bdkTxBuilderFactory: BdkTxBuilderFactory,
  bdkWalletFactory: BdkWalletFactory,
  biometricPrompter: BiometricPrompter,
  datadogRumMonitor: DatadogRumMonitor,
  datadogTracer: DatadogTracer,
  deviceTokenConfigProvider: DeviceTokenConfigProvider,
  fileManagerProvider: (FileDirectoryProvider) -> FileManager,
  logWritersProvider: (LogWriterContextStore) -> List<LogWriter>,
  messageSigner: MessageSigner,
  phoneNumberLibBindings: PhoneNumberLibBindings,
  signatureVerifier: SignatureVerifier,
  secp256k1KeyGenerator: Secp256k1KeyGenerator,
  teltra: Teltra,
  hardwareAttestation: HardwareAttestation,
  deviceOs: DeviceOs,
  wsmVerifier: WsmVerifier,
  cryptoBox: CryptoBox,
  spake2: Spake2,
  symmetricKeyEncryptor: SymmetricKeyEncryptor,
  symmetricKeyGenerator: SymmetricKeyGenerator,
  xChaCha20Poly1305: XChaCha20Poly1305,
  xNonceGenerator: XNonceGenerator,
  firmwareCommsLogBuffer: FirmwareCommsLogBuffer,
  shareGeneratorFactory: ShareGeneratorFactory,
  frostWalletDescriptorFactory: FrostWalletDescriptorFactory,
): AppComponentImpl {
  val appId = AppId(NSBundle.mainBundle.bundleIdentifier!!)
  val appVersion =
    run {
      val info = NSBundle.mainBundle.infoDictionary
      val version = info?.get("CFBundleShortVersionString")
      val build = info?.get("CFBundleVersion")
      AppVersion("$version.$build")
    }
  val platformContext = PlatformContext()
  val fileDirectoryProvider = FileDirectoryProviderImpl(platformContext)
  val fileManager = fileManagerProvider(fileDirectoryProvider)
  val databaseIntegrityChecker = DatabaseIntegrityCheckerImpl(fileDirectoryProvider)

  val logStore = when (appVariant) {
    AppVariant.Development -> LogStoreInMemoryImpl()
    AppVariant.Team -> LogStoreInMemoryImpl()
    AppVariant.Beta -> LogStoreInMemoryImpl()
    AppVariant.Customer -> BoundedInMemoryLogStoreImpl()
    AppVariant.Emergency -> BoundedInMemoryLogStoreImpl()
  }

  return AppComponentImpl(
    appId = appId,
    appVariant = appVariant,
    deviceOs = deviceOs,
    appVersion = appVersion,
    bdkAddressBuilder = bdkAddressBuilder,
    bdkBlockchainFactory = bdkBlockchainFactory,
    bdkBumpFeeTxBuilderFactory = bdkBumpFeeTxBuilderFactory,
    bdkDescriptorSecretKeyGenerator = bdkDescriptorSecretKeyGenerator,
    bdkMnemonicGenerator = bdkMnemonicGenerator,
    bdkPartiallySignedTransactionBuilder = bdkPartiallySignedTransactionBuilder,
    bdkTxBuilderFactory = bdkTxBuilderFactory,
    bdkWalletFactory = bdkWalletFactory,
    datadogRumMonitor = datadogRumMonitor,
    datadogTracer = datadogTracer,
    delayer = Delayer.Default,
    deviceTokenConfigProvider = deviceTokenConfigProvider,
    fileDirectoryProvider = fileDirectoryProvider,
    fileManager = fileManager,
    logStore = logStore,
    logWritersProvider = logWritersProvider,
    messageSigner = messageSigner,
    signatureVerifier = signatureVerifier,
    platformContext = platformContext,
    phoneNumberLibBindings = phoneNumberLibBindings,
    secp256k1KeyGenerator = secp256k1KeyGenerator,
    teltra = teltra,
    hardwareAttestation = hardwareAttestation,
    wsmVerifier = wsmVerifier,
    cryptoBox = cryptoBox,
    spake2 = spake2,
    symmetricKeyEncryptor = symmetricKeyEncryptor,
    symmetricKeyGenerator = symmetricKeyGenerator,
    xChaCha20Poly1305 = xChaCha20Poly1305,
    xNonceGenerator = xNonceGenerator,
    firmwareCommsLogBuffer = firmwareCommsLogBuffer,
    databaseIntegrityChecker = databaseIntegrityChecker,
    shareGeneratorFactory = shareGeneratorFactory,
    frostWalletDescriptorFactory = frostWalletDescriptorFactory
  )
}
