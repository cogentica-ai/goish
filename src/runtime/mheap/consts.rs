// runtime::mheap::consts — page-allocator constants, verbatim from Go's
// runtime/mpagealloc.go and runtime/mpagealloc_64bit.go for amd64.
//
// The radix tree's geometry follows Go exactly so each constant maps
// 1:1 to its source counterpart. The relation is:
//
//   summaryL0Bits + (summaryLevels-1)*summaryLevelBits + logPallocChunkBytes
//     = heapAddrBits
//
// On amd64:
//
//   14 + 4*3 + 22 = 48
//
// — i.e. one root summary covers 16 GiB; each non-root level fans out
// 8-way, and the leaf summary covers one 4 MiB chunk (512 pages of
// 8 KiB each).

#![allow(dead_code)]

// ─── Page geometry ────────────────────────────────────────────────────

/// `pageSize` — bytes per allocator page. Note this is Go's allocator
/// page (8 KiB), not the kernel's MMU page (4 KiB on x86_64). The
/// page allocator manages spans in units of this size.
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;

/// `pageShift` — `log2(PAGE_SIZE)`.
pub const PAGE_SHIFT: u32 = 13;

// ─── Chunk geometry ───────────────────────────────────────────────────

/// `logPallocChunkPages` — `log2` of pages per chunk. Each leaf summary
/// in the radix tree, and each `PallocBits` bitmap, covers exactly this
/// many pages.
pub const LOG_PALLOC_CHUNK_PAGES: u32 = 9;

/// `pallocChunkPages` — pages per chunk = 512.
pub const PALLOC_CHUNK_PAGES: usize = 1 << LOG_PALLOC_CHUNK_PAGES;

/// `logPallocChunkBytes` — `log2` of bytes per chunk = 22 (4 MiB).
pub const LOG_PALLOC_CHUNK_BYTES: u32 = LOG_PALLOC_CHUNK_PAGES + PAGE_SHIFT;

/// `pallocChunkBytes` — bytes per chunk = 4 MiB.
pub const PALLOC_CHUNK_BYTES: usize = 1 << LOG_PALLOC_CHUNK_BYTES;

// ─── Address space (heap-side) ────────────────────────────────────────

/// `heapAddrBits` — number of bits in a heap address. amd64 user
/// virtual address space is 48 bits (the canonical-form architectural
/// max), and we follow Go in addressing the entire 256 TiB.
pub const HEAP_ADDR_BITS: u32 = 48;

// ─── Radix tree geometry ──────────────────────────────────────────────

/// `summaryLevels` — number of levels in the radix tree.
pub const SUMMARY_LEVELS: usize = 5;

/// `summaryLevelBits` — fanout exponent for non-root levels. A value
/// of 3 means each non-root summary covers 8 children, so a block of
/// 8 × 8 B = 64 B summaries fits in one cache line.
pub const SUMMARY_LEVEL_BITS: u32 = 3;

/// `summaryL0Bits` — fanout exponent for the root level. Derived so
/// that the levels span exactly the heap-addressable bits above a
/// chunk:
///
///   summaryL0Bits = heapAddrBits - logPallocChunkBytes
///                                - (summaryLevels-1) * summaryLevelBits
///                 = 48 - 22 - 4*3 = 14
pub const SUMMARY_L0_BITS: u32 =
    HEAP_ADDR_BITS - LOG_PALLOC_CHUNK_BYTES - (SUMMARY_LEVELS as u32 - 1) * SUMMARY_LEVEL_BITS;

/// Per-level bit width (`levelBits` in the Go source).
pub const LEVEL_BITS: [u32; SUMMARY_LEVELS] = [
    SUMMARY_L0_BITS,
    SUMMARY_LEVEL_BITS,
    SUMMARY_LEVEL_BITS,
    SUMMARY_LEVEL_BITS,
    SUMMARY_LEVEL_BITS,
];

/// Per-level shift (`levelShift` in the Go source) — to map an address
/// to a summary index at that level, right-shift the address by this
/// amount.
pub const LEVEL_SHIFT: [u32; SUMMARY_LEVELS] = [
    HEAP_ADDR_BITS - SUMMARY_L0_BITS,
    HEAP_ADDR_BITS - SUMMARY_L0_BITS - SUMMARY_LEVEL_BITS,
    HEAP_ADDR_BITS - SUMMARY_L0_BITS - 2 * SUMMARY_LEVEL_BITS,
    HEAP_ADDR_BITS - SUMMARY_L0_BITS - 3 * SUMMARY_LEVEL_BITS,
    HEAP_ADDR_BITS - SUMMARY_L0_BITS - 4 * SUMMARY_LEVEL_BITS,
];

/// `levelLogPages` — `log2` of the maximum number of runtime pages a
/// summary at the given level represents. The leaf level always
/// represents exactly one chunk's worth of pages.
pub const LEVEL_LOG_PAGES: [u32; SUMMARY_LEVELS] = [
    LOG_PALLOC_CHUNK_PAGES + 4 * SUMMARY_LEVEL_BITS,
    LOG_PALLOC_CHUNK_PAGES + 3 * SUMMARY_LEVEL_BITS,
    LOG_PALLOC_CHUNK_PAGES + 2 * SUMMARY_LEVEL_BITS,
    LOG_PALLOC_CHUNK_PAGES + 1 * SUMMARY_LEVEL_BITS,
    LOG_PALLOC_CHUNK_PAGES,
];

// ─── Packed-summary geometry ──────────────────────────────────────────

/// `logMaxPackedValue` — `log2` of `maxPackedValue`. Each of `start`,
/// `max`, `end` in a `PallocSum` is this many bits wide. For amd64 it
/// works out to 21, just enough that 3*21 = 63 fits in a u64 with one
/// bit (bit 63) left as the "all maxPackedValue" sentinel.
pub const LOG_MAX_PACKED_VALUE: u32 =
    LOG_PALLOC_CHUNK_PAGES + (SUMMARY_LEVELS as u32 - 1) * SUMMARY_LEVEL_BITS;

/// `maxPackedValue` — maximum value any of the three packed fields can
/// take. Equals one full root-level region's worth of pages (2^21 =
/// 2 097 152 pages = 16 GiB).
pub const MAX_PACKED_VALUE: usize = 1 << LOG_MAX_PACKED_VALUE;

// ─── Compile-time sanity ──────────────────────────────────────────────

const _: () = {
    // `PallocSum` packs three `LOG_MAX_PACKED_VALUE`-bit fields plus
    // the sentinel bit — total must fit in 64 bits.
    assert!(3 * LOG_MAX_PACKED_VALUE + 1 <= 64);
    // Levels must span all heap-address bits above a chunk.
    assert!(
        SUMMARY_L0_BITS + (SUMMARY_LEVELS as u32 - 1) * SUMMARY_LEVEL_BITS + LOG_PALLOC_CHUNK_BYTES
            == HEAP_ADDR_BITS
    );
    // Root summary must be able to represent its full page count.
    assert!(LEVEL_LOG_PAGES[0] <= LOG_MAX_PACKED_VALUE);
};
