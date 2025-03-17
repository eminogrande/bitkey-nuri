package build.wallet.platform.pdf

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import okio.ByteString
import okio.ByteString.Companion.EMPTY

@BitkeyInject(AppScope::class)
class PdfAnnotatorImpl : PdfAnnotator {
  override fun close() {
    // Actual working implementation tracked by BKR-898.
  }

  override fun serializeBlocking(): PdfAnnotationResult<ByteString> {
    // Actual working implementation tracked by BKR-898.
    return PdfAnnotationResult.Ok(EMPTY)
  }

  override fun addTextBlocking(
    text: TextAnnotation,
    pageNum: Int,
    frame: PdfFrame,
    url: String?,
  ): PdfAnnotationResult<Unit> {
    // Actual working implementation tracked by BKR-898.
    return PdfAnnotationResult.Ok(Unit)
  }

  override fun addImageDataBlocking(
    data: ByteString,
    pageNum: Int,
    frame: PdfFrame,
    url: String?,
  ): PdfAnnotationResult<Unit> {
    // Actual working implementation tracked by BKR-898.
    return PdfAnnotationResult.Ok(Unit)
  }
}
