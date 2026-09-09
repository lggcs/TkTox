#!/usr/bin/env bash
# env.sh — shared build/run environment for TkTox scripts.
#
# The vendored .deps tree is laid out per multiarch triplet
# (.deps/<pkg>/usr/lib/<triplet>). This helper computes the triplet once
# (from $TT_DEPS_TRIPLET if set, else from the host processor) and exports
# the PKG_CONFIG_PATH chain and the LD_LIBRARY_PATH needed to build and run
# against the vendored libs. Source it, don't execute it:
#     . "$(dirname "$0")/env.sh"
#
# Cross-compiling: set TT_DEPS_TRIPLET (and point PKG_CONFIG_PATH at the
# target's .pc files) before sourcing, e.g.
#     TT_DEPS_TRIPLET=x86_64-linux-gnu . ./env.sh

set -u

# Resolve the multiarch triplet.
if [ -z "${TT_DEPS_TRIPLET:-}" ]; then
    case "$(uname -m)" in
        aarch64|arm64)   TT_DEPS_TRIPLET=aarch64-linux-gnu ;;
        x86_64|amd64)    TT_DEPS_TRIPLET=x86_64-linux-gnu ;;
        riscv64)         TT_DEPS_TRIPLET=riscv64-linux-gnu ;;
        *)               TT_DEPS_TRIPLET="$(uname -m)-linux-gnu" ;;
    esac
fi
export TT_DEPS_TRIPLET

# Root of the vendored dependency tree (inside TkTox/vendor/).
TT_DEPS_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)/vendor/.deps

# pkg-config search path: vendored .pc dirs first, then the system triplet.
TT_PC=""
for pkg in tcl tk sodium opus vpx alsa; do
    TT_PC="$TT_DEPS_ROOT/$pkg/usr/lib/$TT_DEPS_TRIPLET/pkgconfig${TT_PC:+:$TT_PC}"
done
export PKG_CONFIG_PATH="$TT_PC:/usr/lib/$TT_DEPS_TRIPLET/pkgconfig:/usr/share/pkgconfig"

# Vendored Xft is a transitive dep of libtk8.6 not covered by RUNPATH.
export LD_LIBRARY_PATH="$TT_DEPS_ROOT/xft/usr/lib/$TT_DEPS_TRIPLET${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
