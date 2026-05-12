"""
Content-Encoding decoders: zstd (fastest first), gzip, brotli.
`decode(body, encoding)` returns decoded bytes or the original bytes on error.
"""

from __future__ import annotations

import gzip
import logging
import zlib

log = logging.getLogger("Codec")

try:
    import brotli  # type: ignore
    _HAS_BR = True
except ImportError:
    brotli = None
    _HAS_BR = False

try:
    import zstandard as _zstd  # type: ignore
    _HAS_ZSTD = True
    _ZSTD_DCTX = _zstd.ZstdDecompressor()
except ImportError:
    _zstd = None
    _HAS_ZSTD = False
    _ZSTD_DCTX = None


def supported_encodings() -> str:
    """Accept-Encoding value optimized for decompression speed.
    ZSTD first — fastest, then gzip (stdlib), then brotli.
    """
    codecs = []
    if _HAS_ZSTD:
        codecs.append("zstd")
    codecs.append("gzip")
    codecs.append("deflate")
    if _HAS_BR:
        codecs.append("br")
    return ", ".join(codecs)


def has_brotli() -> bool:
    return _HAS_BR


def has_zstd() -> bool:
    return _HAS_ZSTD


def decode(body: bytes, encoding: str) -> bytes:
    if not body:
        return body
    enc = (encoding or "").strip().lower()
    if not enc or enc == "identity":
        return body

    # Multi-layer: "zstd, gzip" means zstd(gzip(data))
    if "," in enc:
        for layer in reversed([s.strip() for s in enc.split(",") if s.strip()]):
            body = decode(body, layer)
        return body

    try:
        if enc == "zstd":
            if not _HAS_ZSTD:
                log.debug("zstandard not installed – body passed through")
                return body
            return _ZSTD_DCTX.decompress(body)
        if enc == "gzip":
            return gzip.decompress(body)
        if enc == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if enc == "br":
            if not _HAS_BR:
                log.debug("brotli not installed – body passed through")
                return body
            return brotli.decompress(body)
    except Exception as exc:
        log.debug("decompress (%s) failed: %s — returning raw", enc, exc)
        return body

    return body