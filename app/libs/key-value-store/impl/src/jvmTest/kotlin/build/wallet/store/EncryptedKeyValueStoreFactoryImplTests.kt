package build.wallet.store

import build.wallet.platform.data.FileDirectoryProviderImpl
import build.wallet.platform.data.FileManagerImpl
import build.wallet.platform.data.filesDir
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import java.io.File
import java.nio.file.Files
import java.nio.file.Path

class EncryptedKeyValueStoreFactoryImplTests : FunSpec({
  test("save and load properties") {
    val directoryProvider = FileDirectoryProviderImpl(null)
    val storeFactory = EncryptedKeyValueStoreFactoryImpl(FileManagerImpl(directoryProvider))

    val dir = directoryProvider.filesDir()
    File(dir).deleteRecursively()
    Files.createDirectories(Path.of(dir))

    val store = storeFactory.getOrCreate("test")
    store.putString("hello", "world")
    store.getStringOrNull("hello").shouldBe("world")

    val newStore = storeFactory.getOrCreate("test")
    newStore.getStringOrNull("hello").shouldBe("world")
  }

  test("same instance of settings is created") {
    val directoryProvider = FileDirectoryProviderImpl(null)
    val storeFactory = EncryptedKeyValueStoreFactoryImpl(FileManagerImpl(directoryProvider))

    storeFactory.getOrCreate("foo").shouldBeSameInstanceAs(storeFactory.getOrCreate("foo"))
    storeFactory.getOrCreate("foo").shouldNotBe(storeFactory.getOrCreate("bar"))
  }
})
