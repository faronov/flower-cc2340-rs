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

> **Status: compiles and is host-tested only.** It has never run on a flower
> board. Every register sequence below still needs a hardware gate (see
> [Limitations](#limitations)).

## Layout

```text
firmware/          cc2340-flower: composition root (LEDs, button, RTT, reboot-on-leave)
    ↓
crates/product/    cc2340-flower-product: identity, flash layout, sensor detection,
                   ZCL profile, measurement, sampling policy, soil/battery maths
    ↓
crates/board/      flower-cc2340r5: pin map, fitted peripherals (I2C bus, soil probe)

From zigbee-rs:
  sensor-sed-app   shared Sleepy End Device lifecycle (SensorApp)
  cc2340r5-hal     clocks, standby, SYSTIM, GPIO, I2C, ADC, LGPT PWM, BATMON,
                   flash, identity, reset
  zigbee-tmp102 / zigbee-bh1750 / zigbee-opt3001   sensor drivers
  zigbee-runtime, zigbee-mac (feature cc2340), zigbee-zcl, ...
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
    detected.
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

1. Before the Zigbee device is built, `boot::resolve_sensors` (in
   `crates/product`) reads the security journal.
2. **Commissioned boot** (for this EUI-64): the persisted `DetectedSensors`
   record is reused and the I2C bus is not touched.
3. **Factory-new boot:**
   - the bus is probed for the TMP102, BH1750 and OPT3001 at the addresses
     above;
   - each detected sensor is put back to sleep;
   - the result is written to its own flash sector if it changed.
4. `profile::flower_profile(sensors)` builds the endpoint from that set. It
   calls `PlantSensor::without_illuminance()` when no light sensor was found,
   so Illuminance is absent from the Simple Descriptor, from reporting and
   from binding.
5. The same `DetectedSensors` value selects the temperature source (TMP102 or
   BATMON) and the light source for measurement.

If both light sensors are fitted, the OPT3001 is used. Host tests cover each
combination: no sensors, TMP102 only, BH1750 only, OPT3001 only, and TMP102
plus a light sensor.

### Flash layout

From `crates/product/link/memory.x`, which `firmware/memory.x` must match
(`firmware/build.rs` enforces this):

```text
0x00000000..0x0007D800  application image (flashed at 0, no bootloader)
0x0007D800..0x0007E000  detected-sensor record (one 2-KiB sector)
0x0007E000..0x00080000  SecurityStateJournal (two 4-KiB logical sectors)
```

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
  read, by `zigbee-mac`'s build script.

```bash
# Host tests (product and board)
cargo test --locked
cargo test --locked -p cc2340-flower-product --no-default-features --features diyzi

# Firmware (run from firmware/ so its .cargo/config.toml applies)
cd firmware
CC2340_SDK_DIR=/absolute/path/to/simplelink-lowpower-f3-sdk \
  cargo build --release --locked

# DIYZi calibration
CC2340_SDK_DIR=... cargo build --release --locked \
  --no-default-features --features diyzi

# Raw image and Intel HEX for programming at address 0
rust-objcopy -O binary ../target/thumbv6m-none-eabi/release/cc2340-flower cc2340-flower.bin
rust-objcopy -O ihex   ../target/thumbv6m-none-eabi/release/cc2340-flower cc2340-flower.hex
```

With `CC2340_SDK_DIR` unset, the image still compiles, but radio
initialization fails closed with `FirmwareUnavailable`. CI checks this
fallback build too.

`Cargo.lock` pins the zigbee-rs revision. To move to a newer zigbee-rs
`master`, run `cargo update -p zigbee-runtime`, which updates all crates from
that repository together.

## Flashing

**Untested.** Program `cc2340-flower.hex` at address 0 with TI UniFlash or
another CC2340R5-capable SWD tool. Use a sector erase of main flash only.

- The image does not contain a CCFG. The board's existing CCFG must keep SWD
  enabled and boot from address 0.
- A mass erase also clears the detection and security sectors, which is
  equivalent to a factory reset.

Diagnostics are printed over RTT.

## Limitations

- **No hardware validation.** The following are written against TI's
  register headers and driverlib but are unverified on silicon:
  - I2C controller, ADC, LGPT PWM, IOC pin mux and CLKCTL gating;
  - the soil-probe settling and conversion timing;
  - LED polarity;
  - standby with DIO20 wake;
  - reboot-on-leave.
- **Soil readings:** the calibration lines come from the reference
  firmware's measurements. Readings from this ADC path have not been
  compared with that firmware.
- **Battery:** a single BATMON read per sample (the reference averages 10).
- **Radio and security:** the same open gates as zigbee-rs's
  `examples/cc2340-sensor` apply:
  - MAC ACK timing is not qualified;
  - the entropy backend fails closed, so commissioning is not claimed;
  - there is no watchdog.
- **No OTA and no MCUboot:** the image is linked at 0 and occupies the whole
  application region. Bootloader and OTA support are a later phase.
- **Image size:** panic locations embed absolute source paths, including the
  cargo git checkout path. The binary is therefore a few hundred bytes larger
  than an equivalent build inside the zigbee-rs tree, and it differs between
  build machines.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option, the same as zigbee-rs.
