#!/bin/sh
# Regenerate the imgtool test vectors used by `src/ota.rs` tests.
#
#   IMGTOOL=/path/to/imgtool MCUBOOT_DIR=/path/to/mcuboot ./generate.sh
#
# TEST-ONLY-ec-p256.pem is a throwaway key committed only so the vectors can
# be reproduced. It must never sign anything installed on a device.
# root-ec-p256.pem is MCUboot's public sample key (TI SDK, koptserg's
# MCUboot); it is read from an MCUboot checkout and not committed here.
set -eu
cd "$(dirname "$0")"
IMGTOOL=${IMGTOOL:-imgtool}
MCUBOOT_DIR=${MCUBOOT_DIR:-/tmp/mcuboot}
PY=$(head -n1 "$(command -v "$IMGTOOL")" | sed 's/^#!//')

[ -f TEST-ONLY-ec-p256.pem ] || "$IMGTOOL" keygen -t ecdsa-p256 -k TEST-ONLY-ec-p256.pem

# 2000-byte deterministic payload.
"$PY" -c 'import sys; sys.stdout.buffer.write(bytes((i * 13 + 5) & 0xFF for i in range(2000)))' > payload.bin

# The flower slot geometry (crates/layout).
COMMON="--header-size 0x100 --pad-header --align 4 --slot-size 0x3D800"
"$IMGTOOL" sign $COMMON --version 1.0.0 --key TEST-ONLY-ec-p256.pem payload.bin test-v1.bin
"$IMGTOOL" sign $COMMON --version 2.0.0 --key TEST-ONLY-ec-p256.pem payload.bin test-v2.bin
"$IMGTOOL" sign $COMMON --version 2.1.0 --key TEST-ONLY-ec-p256.pem payload.bin test-v2.1.bin
"$IMGTOOL" sign $COMMON --version 2.1.0 --key "$MCUBOOT_DIR/root-ec-p256.pem" payload.bin ti-v2.1.bin

"$PY" - TEST-ONLY-ec-p256.pem test-key.xy <<'PYEOF'
import sys
from cryptography.hazmat.primitives import serialization
key = serialization.load_pem_private_key(open(sys.argv[1], "rb").read(), None)
numbers = key.public_key().public_numbers()
open(sys.argv[2], "wb").write(numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big"))
PYEOF
rm payload.bin
