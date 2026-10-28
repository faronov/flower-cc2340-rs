/* CC2340R52 memory map for the flower soil-sensor application.
 *
 * koptserg's MCUboot layout (see crates/layout/src/lib.rs); 2-KiB sectors:
 *   0x00000..0x04000  bootloader (koptserg MCUboot or bootloader/)
 *   0x04000..0x41800  primary slot: MCUboot header 0x04000..0x04100,
 *                     application from 0x04100, TLVs, trailer sector
 *                     0x41000..0x41800
 *   0x41800..0x7F000  secondary slot (OTA download)
 *   0x7F000..0x80000  security journal, two 2-KiB sectors
 *
 * FLASH ends 0x300 bytes before the primary trailer sector so that
 * `imgtool sign` can append the TLV area (about 152 bytes).
 */
MEMORY
{
    FLASH : ORIGIN = 0x00004100, LENGTH = 0x3CC00
    RAM   : ORIGIN = 0x20000000, LENGTH = 36K
}

_primary_slot_start   = 0x00004000;
_primary_trailer      = 0x00041000;
_secondary_slot_start = 0x00041800;
_nv_start             = 0x0007F000;
_nv_end               = 0x00080000;

ASSERT(ORIGIN(FLASH) == _primary_slot_start + 0x100,
  "flower application must start after the 0x100-byte MCUboot header");
ASSERT(ORIGIN(FLASH) + LENGTH(FLASH) + 0x300 == _primary_trailer,
  "flower application must leave 0x300 bytes for TLVs before the trailer sector");
ASSERT(_secondary_slot_start - _primary_slot_start == 0x3D800,
  "flower primary slot must match koptserg's MCUboot (0x3D800)");
ASSERT(_nv_start - _secondary_slot_start == 0x3D800,
  "flower secondary slot must match koptserg's MCUboot (0x3D800)");
ASSERT(_nv_end - _nv_start == 4K && _nv_end == 512K,
  "flower persistent data must be the top 4 KiB (two 2-KiB sectors)");
ASSERT(ORIGIN(RAM) + LENGTH(RAM) == 0x20009000,
  "CC2340R52 RAM region must end at the top of its 36-KiB SRAM");
ASSERT(_stack_start - __euninit >= 16K,
  "CC2340 static task storage must leave at least 16 KiB for the stack");
