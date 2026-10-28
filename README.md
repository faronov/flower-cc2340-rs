# flower-cc2340-rs

Pure-Rust Zigbee firmware for koptserg's CC2340R5 "flower" soil-moisture
board ([flower_CC2340R5_RGE](https://github.com/koptserg/flower_CC2340R5_RGE)).
The board is a CC2340R5 RGE in an Ebyte E104-BT55SP module, powered by a
CR2032. It has a capacitive soil probe and optional I2C temperature and light
sensors.

The Zigbee PRO stack, the CC2340R5 radio driver and chip HAL, the sensor
drivers and the Sleepy End Device lifecycle all come from
[zigbee-rs](https://github.com/faronov/zigbee-rs) as git dependencies. This
repository holds only the board wiring, the product policy and the firmware
composition root. No TI C code is linked. TI's radio microcode and settings
are imported as data at build time.

> **Status: compiles and is host-tested only.** Neither the firmware nor the
> bootloader has run on a flower board, and no OTA upgrade has been performed
> on hardware. Every register sequence and the whole OTA/boot path still need
> hardware gates (see [Hardware checklist](#hardware-checklist)).

## Layout

```text
firmware/          cc2340-flower: composition root (LEDs, button, RTT, reboot-on-leave,
                   OTA wiring, early-start interrupt reset)
bootloader/        flower-boot: 16-KiB overwrite-only loader at 0x0 (own key)
    ↓
crates/product/    cc2340-flower-product: identity, persistent data, sensor detection,
                   ZCL profile, measurement, sampling policy, OTA channel policy,
                   soil/battery maths
crates/layout/     flower-layout: the flash map and the trusted public keys
    ↓
crates/board/      flower-cc2340r5: pin map, fitted peripherals (I2C bus, soil probe)
tools/             flower_ota.py: signing, Zigbee OTA files, full-flash HEX, checker
keys/              public keys only (own key, MCUboot sample key)

From zigbee-rs:
  sensor-sed-app   shared Sleepy End Device lifecycle (SensorApp, OTA lifecycle hooks)
  cc2340r5-hal     clocks, standby, SYSTIM, GPIO, I2C, ADC, LGPT PWM, BATMON,
                   flash, identity, reset
  mcuboot-image    MCUboot image/TLV parsing, P-256 verification, overwrite-only
                   boot decision, secondary-slot FirmwareWriter, LoaderInfo record
  cc2340r5-boot    generic CC2340R5 bootloader core (copy, validate, jump)
  zigbee-tmp102 / zigbee-bh1750 / zigbee-opt3001   sensor drivers
  zigbee-runtime (OTA Upgrade client), zigbee-mac (feature cc2340), zigbee-zcl, ...
```

## Board and pin map

| Function | DIO | Notes |
|---|---:|---|
| Green LED | 3 | active high, 1 kΩ to GND (LF RCOSC is used, so DIO3/4 are free) |
| Red LED | 4 | active high, 1 kΩ to GND |
| Button SW1 | 20 | active low, internal pull-up, falling-edge standby wake |
| I2C0 SDA | 8 | PFUNC4, internal pull-up |
| I2C0 SCL | 6 | PFUNC2, internal pull-up |
| Soil probe excitation | 24 | LGPT1 channel 0 PWM, 2 MHz, 50 %, idle low (PFUNC2) |
| Soil probe detector | 21 | ADC channel 10, VDDS reference, 12-bit |
| SWD | 16 / 17 | SWDIO / SWDCK |

Optional I2C sensors (address pins as on the schematic):

| Sensor | Address pin | 7-bit address | Used for |
|---|---|---:|---|
| TMP102 | ADD0 = GND | 0x48 | temperature |
| BH1750 | ADDR = GND | 0x23 | illuminance |
| OPT3001 | ADDR = GND | 0x44 | illuminance (identified by its manufacturer and device ID registers) |

## Behaviour

- **Role:** battery Sleepy End Device; device standby between polls.
- **Identity:** manufacturer `zigbee-rs`, model `CC2340-Flower`, endpoint 1.
- **Clusters:**
  - always present: Basic, Identify, Power Configuration (battery),
    Soil Moisture (0x0408) and Temperature Measurement (0x0402);
  - Illuminance Measurement (0x0400): only when a BH1750 or OPT3001 was
    detected;
  - OTA Upgrade (0x0019) client.
- **Temperature source:** the TMP102 if one is fitted, otherwise the BATMON
  die-temperature sensor.
- **Soil moisture:**
  1. Run the 2 MHz PWM and take 10 ADC conversions, averaged in µV.
  2. Stop the PWM.
  3. Map the average linearly between the supply-dependent AIR and WATER
     calibration lines and clamp to 0–100 %. The ZCL value is % × 100.
- **Battery:** the BATMON supply voltage, mapped 2.0–3.0 V to 0–100 %. The
  ZCL value is % × 2.
- **Illuminance:** the ZCL value is 10000·log10(lux) + 1, computed with an
  integer approximation.
- **Sampling cadence** (5-minute periodic tick):

  | Measurement | Interval |
  |---|---|
  | Temperature and illuminance | every 5 min |
  | Soil | every 10 min |
  | Battery | hourly |

  A button press or a fresh join samples everything immediately.
- **Peripheral power:** peripherals are on only while measuring.
  - PWM and ADC run only during the soil read.
  - The TMP102 and OPT3001 run single conversions and return to shutdown.
  - The BH1750 runs one-time mode and powers down again.
  - The I2C controller is clock-gated between transactions.
- **Button SW1:**
  - *Short press:* report now when joined; start joining when not joined.
  - *Hold 5 s:* leave and factory reset. The red LED blinks three times,
    then the device reboots.
- **LEDs:**
  - green blink: a network search is running;
  - three green blinks: joined;
  - green: reporting or identifying;
  - three red blinks: reset or leave;
  - steady red: fatal fault.
- **Leaving:** after any network leave (button, Mgmt_Leave, or Trust Center
  removal) the firmware waits 2 s and reboots. The next boot is factory-new,
  so it re-detects the sensors and starts commissioning.

### Sensor autodetection

The Simple Descriptor must not change while the device is joined. The cluster
set is therefore built at runtime from a persisted detection result, never
from cargo features.

1. Before the Zigbee device is built, `boot::open` (in `crates/product`)
   reads the security journal.
2. **Commissioned boot** (for this EUI-64): the persisted `DetectedSensors`
   record is reused and the I2C bus is not touched.
3. **Factory-new boot:**
   - the bus is probed for the TMP102, BH1750 and OPT3001 at the addresses
     above;
   - each detected sensor is put back to sleep;
   - the result becomes the journal's product tag, so it is committed
     atomically with the first security-state record of the new network.
4. `profile::flower_profile(sensors)` builds the endpoint from that set. It
   calls `PlantSensor::without_illuminance()` when no light sensor was found,
   so Illuminance is absent from the Simple Descriptor, from reporting and
   from binding.
5. The same `DetectedSensors` value selects the temperature source (TMP102 or
   BATMON) and the light source for measurement.

If both light sensors are fitted, the OPT3001 is used. Host tests cover each
combination: no sensors, TMP102 only, BH1750 only, OPT3001 only, and TMP102
plus a light sensor.

## Flash layout

koptserg's MCUboot layout (`mcuboot_flower_CC2340R5_RGE/mcuboot.syscfg`),
kept identical so that boards running his bootloader can install this
firmware over the air. `crates/layout` holds the map; both `memory.x` files
and the tooling are checked against it.

| Range | Size | Contents |
|---|---:|---|
| `0x00000..0x04000` | 16 KiB | bootloader: koptserg's MCUboot, or `bootloader/` with its LoaderInfo record at `0x3FE0` |
| `0x04000..0x41800` | 246 KiB | primary slot: MCUboot header (`0x100`), application from `0x04100`, TLVs; trailer in the last 2-KiB sector |
| `0x41800..0x7F000` | 246 KiB | secondary slot: OTA download area |
| `0x7F000..0x80000` | 4 KiB | persistent data: security journal, two 2-KiB sectors |

The CCFG is a separate flash region and is never written. Its default
`pAppVtor = 0` starts whichever loader sits at `0x0`.

- **Image size.** The application may use `0x04100..0x40D00` (248 832 B).
  The linker asserts this and keeps `0x300` bytes free for imgtool's TLVs.
  The rest of the slot's last sector holds the trailer.
- **Persistent data in 4 KiB.** The earlier bootloader-less layout had 12 KiB
  (a detection sector plus two 4-KiB journal sectors). Now:
  - the zigbee-rs `SecurityStateJournal` runs with 2-KiB logical sectors
    (16 records of 128 B);
  - the detected-sensor set is the journal's 16-bit product tag, written in
    every record at no extra flash cost.

  The journal's power-fail argument is unchanged. A rollover writes the
  replay snapshot and then the state record into the freshly erased other
  sector, and the old sector stays authoritative until that last record
  commits. Frame counters are reserved ahead of use, so a reset never
  reuses one. The cost is endurance: with every replay domain populated, a
  rollover leaves about 12 commits per erase; a SED with a handful of peers
  gets about 56. Host tests on a mock flash cut power at every write and
  erase of 40 tagged commits, which includes rollovers on the 2-KiB
  geometry. They also cut power inside the first commit and during the
  foreign-data erase. After every cut, the reloaded counter limit is never
  below an acknowledged one.
- **Foreign data.** At boot, `storage::prepare_nv` keeps the partition only
  if it is erased or its newest committed record carries a valid flower
  tag. Anything else is erased, and the board starts factory-new. Examples:
  ZBOSS NVS from koptserg's firmware, or a journal from the bootloader-less
  layout. The erase is idempotent, so an interrupted erase runs again on the
  next boot.

## OTA and bootloaders

The firmware contains a Zigbee OTA Upgrade client (zigbee-runtime
`OtaManager`).

- **Policy:**
  - **Queries:** Query Next Image 5 minutes after joining, then daily. An
    Image Notify from the server triggers a query too.
  - **Offers:** declined while the last compensated supply reading is below
    2.5 V, or before the first reading.
  - **During a download:** fast poll. The device returns to normal polling
    2 minutes after the last OTA traffic.
- **Download path:** `mcuboot_image::SlotWriter` writes the image to the
  secondary slot through `storage::OtaFlash`. That view can erase and write
  only `0x41800..0x7F000`, never the running image or the persistent data.
  - Sectors are erased lazily as the download reaches them.
  - When the download completes, the writer checks the SHA-256 and P-256
    signature against this channel's key, the header size (`0x100`) and
    downgrade against the running image.
  - Only then does it write the MCUboot upgrade request (the trailer magic).
    This happens even for `--pad`ded images, which already carry the magic,
    so an interrupted or rejected download never leaves a request behind.
  - The security state is checkpointed and the device resets into the
    bootloader.

### Channels

The application binary is the same under both bootloaders. At boot it reads
`0x3FE0` to find out which loader it runs under. Only the signing key and the
advertised OTA identity differ:

| Loader at `0x0` | Channel | Manufacturer | Image type | Signing key |
|---|---|---|---|---|
| `bootloader/` (this repo) | `own` | `0x1234` | `0x2341` koptserg, `0x2342` DIYZi | own key |
| koptserg's MCUboot (no LoaderInfo) | `migrate` | `0xBEBE` koptserg, `0xBABA` DIYZi | `0x2340` | MCUboot sample key `root-ec-p256.pem` |
| a LoaderInfo trusting another key | foreign | — | — | every offer declined |

- **Own manufacturer code.** `0x1234` is the zigbee-rs development
  manufacturer code, not an assigned one. Coordinators match OTA files only
  by the code, image type and version, so the `own` channel works anyway.
- **File version.** The OTA file version is `0x25MMmmpp`, from the
  workspace version `MM.mm.pp` (currently 2.0.0, so `0x25020000`). It is
  newer than every koptserg release: `0x24000013` (koptserg) and
  `0x24100013` (DIYZi) are the highest. The MCUboot image version is the
  same `MM.mm.pp`. It starts at 2.0.0 because koptserg signs 1.0.0 and
  MCUboot's downgrade prevention compares these versions.

### Migrating a board that runs koptserg's firmware

1. Build the firmware for the board's calibration (`koptserg` for `BEBE`
   boards, `diyzi` for `BABA` boards) and run `tools/flower_ota.py release`
   (below). This produces `BEBE-2340-25MMmmpp-…-migrate.zigbee` or
   `BABA-2340-…`: signed with `root-ec-p256.pem`, padded to the full slot
   like koptserg's own releases.
2. Offer it from the coordinator's local OTA index. In Zigbee2MQTT use
   `ota.zigbee_ota_override_index_location`; in ZHA use a local OTA provider.
   koptserg's firmware downloads it, and his MCUboot verifies it with the
   same public key and installs it.
3. The board boots this firmware with an empty network state. It cannot read
   ZBOSS NVS, so it erases `0x7F000..0x80000` and comes up factory-new.
4. Press SW1 to join again. The coordinator sees a new device with
   manufacturer `zigbee-rs` and model `CC2340-Flower`. Remove the old
   koptserg entry; reporting and bindings are set up again on interview.

A migrated board keeps koptserg's MCUboot for good: replacing the loader
over the air is not power-fail safe. Its updates therefore stay on the
`migrate` channel, signed with the public sample key, which anyone can sign
with. That gives no more authenticity than koptserg's own releases had. For
signed updates, flash `bootloader/` over SWD (next section).

### Our bootloader (`bootloader/`)

A pure-Rust, overwrite-only loader built from zigbee-rs `cc2340r5-boot` and
`mcuboot-image`. It reads imgtool's image format and uses the same slot
geometry as koptserg's MCUboot. On every reset it:

1. **Installs a pending update.** If the secondary slot ends with the
   upgrade request magic and holds a valid image (SHA-256 TLV, ECDSA P-256
   signature with the own key, geometry) that is not older than the primary,
   it is copied to the primary.
   - The request stays in place until the primary holds a complete,
     validated copy, so an interrupted copy resumes on the next boot.
   - The secondary's trailer and header sectors are then erased.
   - Invalid or downgrade requests are dropped without touching the primary.
   - The green LED blinks while copying.
2. **Validates the primary** (hash and signature) and checks its vector
   table.
3. **Jumps to `0x4100`** with VTOR and MSP set.
4. **With nothing bootable:** blinks the red LED ten times and enters
   SHUTDOWN. SW1, a power cycle or a debugger reset retries. Recovery is
   SWD.

It uses about 9 KB of the 16 KiB. ECDSA P-256 verification is done in the
loader itself, in pure Rust. The application also verifies before
activating, so a bad download costs no copy.

The application does not rely on the loader to initialize the chip. Its
`__pre_init` masks and clears every NVIC interrupt, stops SysTick and clears
pending exceptions. cortex-m-rt's `set-vtor`/`set-sp` then point VTOR at
`0x4100`. This is needed because koptserg's MCUboot does not set VTOR.

### Keys

- **`keys/own-ec-p256.pub.pem` / `.xy.hex`:** the public half of this
  project's signing key. It is built into `bootloader/` and into the
  firmware's `own` channel.
  - The private key is not in the repository; keep it outside the tree, for
    example in `~/.flower-keys/`.
  - To use another key, generate it with `imgtool keygen -t ecdsa-p256 -k
    my.pem`. Then point `FLOWER_OWN_KEY_XY` at a file holding its 64-byte
    `X || Y` in hex for the builds, and pass `--own-key my.pem` (or
    `FLOWER_OWN_KEY`) to the tool.
- **`keys/ti-root-ec-p256.*`:** the public half of MCUboot's sample key,
  which TI's SDK and koptserg's MCUboot use. Its private half is published
  with MCUboot (`root-ec-p256.pem`); the tool reads it from `--ti-key`,
  `$FLOWER_TI_KEY` or `$CC2340_SDK_DIR/source/third_party/mcuboot/`.
- **`crates/product/tests/vectors/TEST-ONLY-ec-p256.pem`:** a throwaway key
  for the host-test vectors. Never trust it on a device.

CI never sees the private key. Every run generates an ephemeral own key,
builds the loader and firmware for it and signs with it, so CI artifacts are
test builds. The `migrate` files from CI are signed with the real (public)
sample key but embed the ephemeral own key.

## Variants

The two published board builds use different soil calibrations. Pick one
with a feature; exactly one must be enabled.

| Feature | Supply compensation | AIR line (µV) | WATER line (µV) |
|---|---|---|---|
| `koptserg` (default) | +20 mV | 148·V + 1 953 000 | 133·V + 800 000 |
| `diyzi` | +10 mV | 197·V + 1 600 000 | 148·V + 900 000 |

V is the compensated supply voltage in mV.

## Build

You need:

- the toolchain pinned in `rust-toolchain.toml`: `nightly-2026-03-23`,
  `thumbv6m-none-eabi`, `rust-src` and `llvm-tools`;
- for a working radio, the TI SimpleLink Low Power F3 SDK sources at commit
  `68ca021502383f367d0bf2a5517fdd0dcb0ef909` (the commit zigbee-rs CI pins).
  Only `source/ti/devices/cc23x0r5` and `source/ti/devices/radioconfig` are
  read, by `zigbee-mac`'s build script;
- for release files: Python ≥ 3.11 and `pip install imgtool` (CI pins
  2.4.0).

```bash
# Host tests (board, layout, product) and the tooling tests
cargo test --locked
cargo test --locked -p cc2340-flower-product --no-default-features --features diyzi
python3 -m unittest discover -s tools

# Bootloader (no SDK needed)
(cd bootloader && cargo build --release --locked)
rust-objcopy --gap-fill 0xff -O binary \
  target/thumbv6m-none-eabi/release/flower-boot flower-boot.bin

# Firmware, from firmware/ so its .cargo/config.toml applies
cd firmware
CC2340_SDK_DIR=/absolute/path/to/simplelink-lowpower-f3-sdk \
  cargo build --release --locked
CC2340_SDK_DIR=... cargo build --release --locked \
  --no-default-features --features diyzi,quiet --target-dir ../target/diyzi
cd ..

# Sign and package: migrate + own .zigbee files and the own full-flash HEX
python3 tools/flower_ota.py release --variant koptserg \
  --app-elf target/thumbv6m-none-eabi/release/cc2340-flower \
  --ti-key /path/to/mcuboot/root-ec-p256.pem \
  --own-key ~/.flower-keys/flower-own-ec-p256.pem \
  --loader-bin flower-boot.bin --out dist
python3 tools/flower_ota.py check dist/*.zigbee
```

With `CC2340_SDK_DIR` unset, the firmware still compiles, but radio
initialization fails closed with `FirmwareUnavailable`. CI checks this
fallback build too.

`tools/flower_ota.py release` writes these files to `dist/`:

| File | Use |
|---|---|
| `flower-<variant>-<ver>-unsigned.bin` | raw application (`0x4100..`) |
| `…-migrate-signed.bin`, `…-own-signed.bin` | MCUboot images (`imgtool sign --header-size 0x100 --pad-header --align 4 --slot-size 0x3D800`; migrate adds `--pad`) |
| `BEBE-2340-…-migrate.zigbee` / `BABA-2340-…` | OTA file for boards under koptserg's MCUboot |
| `1234-2341-…-own.zigbee` / `1234-2342-…` | OTA file for boards under `bootloader/` |
| `flower-<variant>-<ver>-own-full.hex` | `bootloader/` at `0x0` plus the own-signed image at `0x4000`, for SWD |

The tool writes the OTA file header itself (ZCL OTA file format, one
Upgrade Image element). It reproduces the headers of koptserg's
`zOTAfileGen` files byte for byte, which a unit test checks. `check`
validates:

- the header and element;
- the MCUboot header, SHA-256 TLV and signature presence;
- the padding rules of each channel;
- that the file version matches the image version and exceeds koptserg's.

It refuses a full-flash HEX whose loader trusts another key than
`--own-key`.

### Features

| Feature | Default | Effect |
|---|---|---|
| `koptserg` / `diyzi` | `koptserg` | soil calibration (exactly one) |
| `quiet` | yes | compiles every `log` call out of release builds (about 60 KB) |
| `logs` | no | RTT logging, warnings and errors only in release: `--no-default-features --features koptserg,logs`. Info-level logs do not fit the slot. |

`Cargo.lock` pins the zigbee-rs revision. To move to a newer zigbee-rs
`master`, run `cargo update -p zigbee-runtime`, which updates all crates from
that repository together.

## Flashing

**Untested.** Use TI UniFlash or another CC2340R5-capable SWD tool, and
erase main-flash sectors only.

- **New board, or one being moved to `bootloader/`:** program
  `flower-<variant>-<ver>-own-full.hex`. It writes `0x0..` and the primary
  slot only.
  - Erase `0x41800..0x7F000` first if the secondary slot may hold a stale
    request.
  - Erase `0x7F000..0x80000` for a clean start; foreign data there is
    erased at boot anyway.
- **Board kept on koptserg's MCUboot:** program `…-migrate-signed.bin` at
  `0x4000`, or use OTA as described above.
- **The CCFG** must keep SWD enabled and boot from `0x0`.

Program the bootloader and the image together: the application alone at
`0x4100` does not start without a loader at `0x0`.

## Limitations

- **No hardware validation.** See the checklist below.
- **Soil readings:** the calibration lines come from the reference
  firmware's measurements. Readings from this ADC path have not been
  compared with that firmware.
- **Battery:** a single BATMON read per sample (the reference averages 10).
- **Radio and security:** the same open gates as zigbee-rs's
  `examples/cc2340-sensor` apply:
  - MAC ACK timing is not qualified;
  - the entropy backend fails closed, so commissioning is not claimed;
  - there is no watchdog.
- **Migration:**
  - it loses the network membership (rejoin required);
  - coordinators need a definition for the new identity (`zigbee-rs` /
    `CC2340-Flower`);
  - migrated boards stay on the publicly signable `migrate` channel.
- **Journal endurance** is lower than with 4-KiB sectors (see Flash layout).
- **Image size:** panic locations embed absolute source paths, including the
  cargo git checkout path. The binary is therefore a few hundred bytes larger
  than an equivalent build inside the zigbee-rs tree, and it differs between
  build machines.

## Hardware checklist

Each of these is unverified until run on a board:

1. **Peripherals:**
   - I2C controller, ADC, LGPT PWM, IOC pin mux and CLKCTL gating;
   - soil-probe settling and timing;
   - LED polarity;
   - standby with DIO20 wake;
   - reboot-on-leave.
2. **`bootloader/` starts at reset from the CCFG default.** Check its LED
   indication, P-256 verification time, and the jump to `0x4100` (VTOR, MSP).
   With an invalid primary and no request, check the red blink, SHUTDOWN and
   SW1 wake.
3. **The application under koptserg's MCUboot:** `__pre_init`, VTOR, and
   clock and power state handed over by MCUboot.
4. **Flash erase and program from the running application** into the
   secondary slot while the radio is active, including lazy sector erase
   timing against poll and ACK deadlines.
5. **OTA download from Zigbee2MQTT and ZHA:**
   - block size 48 and fast poll;
   - Image Notify handling;
   - Upgrade End;
   - the request write;
   - the reset.
6. **The loader copy**, with power cut at random points (resume), downgrade
   and wrong-key rejection on hardware.
7. **Migration from koptserg's firmware** (BEBE and BABA):
   - the OTA offer is accepted;
   - his MCUboot installs the image;
   - the first boot erases ZBOSS NVS;
   - rejoin;
   - a second migrate-channel update.
8. **BATMON battery guard** at about 2.5 V on a real CR2032 under radio
   load.
9. **Current consumption** while idle, during the download and during the
   loader copy.
10. **Commissioned state retained** across an `own`-channel upgrade (rejoin
    without a new association).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option, the same as zigbee-rs.
