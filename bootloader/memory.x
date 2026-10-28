/* CC2340R52 memory map for the flower bootloader.
 *
 * The loader owns 0x00000..0x04000 (koptserg's MCUboot partition). Its last
 * 32 bytes hold the LoaderInfo record the application reads to detect this
 * loader and its trusted key (crates/layout/src/lib.rs).
 */
MEMORY
{
    FLASH       : ORIGIN = 0x00000000, LENGTH = 0x3FE0
    LOADER_INFO : ORIGIN = 0x00003FE0, LENGTH = 32
    RAM         : ORIGIN = 0x20000000, LENGTH = 36K
}

SECTIONS
{
    .loader_info ORIGIN(LOADER_INFO) :
    {
        KEEP(*(.loader_info));
    } > LOADER_INFO
} INSERT AFTER .rodata;

ASSERT(SIZEOF(.loader_info) == 32,
  "the LoaderInfo record must be exactly 32 bytes");
ASSERT(ORIGIN(LOADER_INFO) + LENGTH(LOADER_INFO) == 0x4000,
  "the bootloader must end at the primary slot (0x4000)");
