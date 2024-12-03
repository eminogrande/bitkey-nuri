package build.wallet.database

import build.wallet.database.sqldelight.BitkeyDatabase
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.io.File

class SqlDelightTests : FunSpec({

  /**
   * If this test fails, you probably forgot to generate and commit the .db file
   * run `just generate-db-schema`.
   */
  test("verify correct number of databases") {
    // check number of databases
    val directory = File("src/commonMain/sqldelight/databases")
    directory.listFiles { _, name ->
      name.endsWith(".db")
    }?.size.shouldBe(BitkeyDatabase.Schema.version)
  }

  // if this test fails, you're trying to update the db schema without adding a migration
  test("verify correct number of migrations") {
    // check number of migrations
    val directory = File("src/commonMain/sqldelight/migrations")
    val files = directory.listFiles { _, name ->
      name.endsWith(".sqm")
    }
      // No directory found, thus no migrations
      .orEmpty()

    files.size.shouldBe(BitkeyDatabase.Schema.version - 1)
  }
})
