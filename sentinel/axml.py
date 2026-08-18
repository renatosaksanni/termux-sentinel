"""Binary AndroidManifest.xml (AXML) decoder, pure Python.

An APK ships its manifest as a compiled binary resource chunk, not as text.
Reading it normally means calling `aapt`, which does not exist as an ARM64
build. Rather than depend on a toolchain we cannot install, this module decodes
the format directly.

Chunk layout follows AOSP's ResourceTypes.h. Only the XML subset is handled --
enough to recover the package name, SDK levels, permissions, and components,
which is all the risk engine needs.

The decoder is deliberately defensive: a malformed or deliberately corrupted
manifest is an attacker-controlled input, so every read is bounds-checked and
failures raise AxmlError instead of producing bogus data.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

UTF8_FLAG = 1 << 8

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

# Framework attributes carry no name in the string pool of manifests produced
# by newer aapt2; the name must be recovered from the resource-map chunk. Only
# well-known, stable public IDs are listed. The pool name always wins when
# present, so a wrong guess here can never override real data.
ATTR_IDS = {
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000B: "sharedUserId",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010280: "allowBackup",
}


class AxmlError(Exception):
    """Raised when the input is not a manifest we can trust."""


class _Reader:
    """Bounds-checked little-endian cursor over the chunk buffer."""

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def seek(self, pos: int) -> None:
        if not 0 <= pos <= len(self.buf):
            raise AxmlError(f"seek out of range: {pos}")
        self.pos = pos

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise AxmlError("truncated chunk")
        b = self.buf[self.pos : self.pos + n]
        self.pos += n
        return b

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return struct.unpack_from("<H", self._take(2))[0]

    def u32(self) -> int:
        return struct.unpack_from("<I", self._take(4))[0]

    def at_u32(self, pos: int) -> int:
        if pos + 4 > len(self.buf):
            raise AxmlError("offset out of range")
        return struct.unpack_from("<I", self.buf, pos)[0]

    @property
    def remaining(self) -> int:
        return len(self.buf) - self.pos


class StringPool:
    """Lazily decoded string pool supporting both UTF-8 and UTF-16 variants."""

    def __init__(self, r: _Reader, chunk_start: int) -> None:
        r.seek(chunk_start)
        chunk_type = r.u16()
        if chunk_type != RES_STRING_POOL:
            raise AxmlError(f"expected string pool, got 0x{chunk_type:04x}")
        r.u16()  # header size
        chunk_size = r.u32()
        count = r.u32()
        r.u32()  # style count
        flags = r.u32()
        strings_start = r.u32()
        r.u32()  # styles start

        self.utf8 = bool(flags & UTF8_FLAG)
        self.count = count
        self._data_base = chunk_start + strings_start
        self._buf = r.buf
        self._limit = min(len(r.buf), chunk_start + chunk_size)
        self._offsets = [r.u32() for _ in range(count)]
        self._cache: dict[int, str] = {}

    def _len_utf16(self, pos: int) -> tuple[int, int]:
        n = struct.unpack_from("<H", self._buf, pos)[0]
        if n & 0x8000:
            hi = n & 0x7FFF
            lo = struct.unpack_from("<H", self._buf, pos + 2)[0]
            return (hi << 16) | lo, pos + 4
        return n, pos + 2

    def _len_utf8(self, pos: int) -> tuple[int, int]:
        n = self._buf[pos]
        if n & 0x80:
            n = ((n & 0x7F) << 8) | self._buf[pos + 1]
            return n, pos + 2
        return n, pos + 1

    def get(self, index: int) -> str:
        # 0xFFFFFFFF is the canonical "no string" marker in AXML.
        if index == 0xFFFFFFFF or index >= self.count or index < 0:
            return ""
        if index in self._cache:
            return self._cache[index]
        try:
            pos = self._data_base + self._offsets[index]
            if pos >= self._limit:
                raise AxmlError("string offset past chunk")
            if self.utf8:
                _, pos = self._len_utf8(pos)  # UTF-16 length, unused
                blen, pos = self._len_utf8(pos)
                raw = self._buf[pos : pos + blen]
                s = raw.decode("utf-8", "replace")
            else:
                clen, pos = self._len_utf16(pos)
                raw = self._buf[pos : pos + clen * 2]
                s = raw.decode("utf-16-le", "replace")
        except (AxmlError, IndexError, struct.error):
            s = ""
        self._cache[index] = s
        return s


@dataclass
class Element:
    """One XML start tag with its attributes flattened to strings."""

    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    depth: int = 0
    parent: str = ""

    def get(self, key: str, default: str = "") -> str:
        return self.attrs.get(key, default)

    def get_int(self, key: str, default: int = 0) -> int:
        raw = self.attrs.get(key, "")
        try:
            return int(raw, 0) if raw else default
        except ValueError:
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        raw = self.attrs.get(key, "").lower()
        if raw in ("true", "1"):
            return True
        if raw in ("false", "0"):
            return False
        return default


def _format_value(pool: StringPool, data_type: int, data: int, raw_index: int) -> str:
    """Render a typed attribute value the way aapt would print it."""
    if raw_index != 0xFFFFFFFF:
        s = pool.get(raw_index)
        if s:
            return s
    if data_type == TYPE_STRING:
        return pool.get(data)
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data else "false"
    if data_type == TYPE_INT_HEX:
        return f"0x{data:x}"
    if data_type == TYPE_REFERENCE:
        return f"@0x{data:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{data:08x}"
    if data_type == TYPE_NULL:
        return ""
    if data_type == TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", data))[0])
    # Signed decimals arrive as unsigned 32-bit words.
    if data_type == TYPE_INT_DEC:
        return str(data - (1 << 32) if data >= (1 << 31) else data)
    return str(data)


def parse(buf: bytes) -> list[Element]:
    """Decode an AXML document into a flat list of start elements.

    A flat list rather than a tree: the manifest queries we care about are all
    "find every <uses-permission>" style lookups, and `parent`/`depth` retain
    the little structural context that matters.
    """
    if len(buf) < 8:
        raise AxmlError("input too small")

    r = _Reader(buf)
    magic = r.u16()
    if magic != RES_XML:
        raise AxmlError(f"not an AXML document (magic 0x{magic:04x})")
    header_size = r.u16()
    total = r.u32()
    if total > len(buf):
        # Some packers pad or truncate; keep going against what we actually have.
        total = len(buf)

    pos = header_size if header_size >= 8 else 8
    pool: StringPool | None = None
    res_map: list[int] = []
    elements: list[Element] = []
    stack: list[str] = []

    while pos + 8 <= total:
        chunk_type = struct.unpack_from("<H", buf, pos)[0]
        chunk_size = struct.unpack_from("<I", buf, pos + 4)[0]
        if chunk_size < 8 or pos + chunk_size > total:
            break  # corrupt chunk table; stop rather than loop forever

        if chunk_type == RES_STRING_POOL:
            pool = StringPool(r, pos)

        elif chunk_type == RES_XML_RESOURCE_MAP:
            n = (chunk_size - 8) // 4
            res_map = [struct.unpack_from("<I", buf, pos + 8 + i * 4)[0] for i in range(n)]

        elif chunk_type == RES_XML_START_ELEMENT:
            if pool is None:
                raise AxmlError("start element before string pool")
            r.seek(pos + 8)
            r.u32()  # line number
            r.u32()  # comment index
            r.u32()  # namespace index
            name_idx = r.u32()
            attr_start = r.u16()
            attr_size = r.u16()
            attr_count = r.u16()
            r.u16()  # id index
            r.u16()  # class index
            r.u16()  # style index

            el = Element(
                name=pool.get(name_idx),
                depth=len(stack),
                parent=stack[-1] if stack else "",
            )

            # attributeStart is measured from the start of ResXMLTree_attrExt,
            # which begins after the 8-byte chunk header plus lineNumber and
            # comment (4 bytes each) -- i.e. 16 bytes into the chunk.
            base = pos + 16 + attr_start
            stride = attr_size if attr_size >= 20 else 20
            for i in range(attr_count):
                ap = base + i * stride
                if ap + 20 > pos + chunk_size:
                    break
                a_name = struct.unpack_from("<I", buf, ap + 4)[0]
                a_raw = struct.unpack_from("<I", buf, ap + 8)[0]
                a_dtype = buf[ap + 15]
                a_data = struct.unpack_from("<I", buf, ap + 16)[0]

                key = pool.get(a_name)
                if not key and a_name < len(res_map):
                    rid = res_map[a_name]
                    key = ATTR_IDS.get(rid, f"attr_0x{rid:08x}")
                if not key:
                    key = f"attr_{i}"
                # The namespace index is ignored: manifest lookups are all on
                # android: attributes, and pool names are already unprefixed.
                el.attrs[key] = _format_value(pool, a_dtype, a_data, a_raw)

            elements.append(el)
            stack.append(el.name)

        elif chunk_type == RES_XML_END_ELEMENT:
            if stack:
                stack.pop()

        pos += chunk_size

    if pool is None:
        raise AxmlError("no string pool found")
    return elements
