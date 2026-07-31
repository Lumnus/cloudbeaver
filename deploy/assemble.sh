#!/usr/bin/env bash
# Assemble the CloudBeaver runtime tree at deploy/cloudbeaver/, ready for deploy/docker/Dockerfile.
#
# This is deploy/build-backend.sh + build-frontend.sh reduced to their COPY steps, with the compile
# steps optional. It exists because the compile cannot happen inside a docker build: the backend
# needs the `dbeaver` and `dbeaver-common` repos as SIBLINGS of this checkout, which a single build
# context cannot express (the two-phase-build gap in docs/rules/optional/fork-build-publish.md).
#
#   ./assemble.sh              # copy only — expects backend + frontend already built
#   ./assemble.sh --build      # also run the maven and yarn builds first
#
# Toolchain, when --build is used: JDK 21 + maven, node 22 + corepack-enabled yarn 4.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$(cd .. && pwd)"
OUT="./cloudbeaver"

BACKEND_PRODUCT="$ROOT/server/product/web-server/target/products/io.cloudbeaver.product/all/all/all"
FRONTEND_LIB="$ROOT/webapp/packages/product-default/lib"

step() { printf '\n\033[1m[assemble] %s\033[0m\n' "$*"; }

if [[ "${1:-}" == "--build" ]]; then
  step "backend (maven/Tycho)"
  # Sibling repos, exactly as build-backend.sh expects them.
  ( cd "$ROOT/.." \
    && [ ! -d dbeaver ]        && git clone --depth 1 https://github.com/dbeaver/dbeaver.git        || true
    [ ! -d dbeaver-common ]    && git clone --depth 1 https://github.com/dbeaver/dbeaver-common.git || true ) || true
  ( cd "$ROOT/server/product/aggregate" && mvn -B clean verify -Dheadless-platform )

  step "frontend (yarn)"
  # corepack is REQUIRED: package.json pins yarn@4.x and the image's global yarn is 1.x, which
  # fails with a packageManager mismatch rather than falling back.
  ( cd "$ROOT/webapp" \
      && corepack enable \
      && yarn install --immutable \
      && yarn clear \
      && ( cd common-react && yarn clear ) \
      && ( cd common-typescript && yarn clear ) \
      && ( cd packages/product-default && yarn run bundle ) )
fi

step "verify build outputs exist before copying"
[ -d "$BACKEND_PRODUCT" ] || { echo "  ✗ backend product missing: $BACKEND_PRODUCT (run with --build)"; exit 1; }
[ -d "$FRONTEND_LIB" ]    || { echo "  ✗ frontend lib missing: $FRONTEND_LIB (run with --build)"; exit 1; }
# The whole point of the fork — fail loudly rather than shipping an image without it.
if ! ls "$BACKEND_PRODUCT"/plugins/io.lumnus.dbeaver.auth.openbao_*.jar >/dev/null 2>&1; then
  echo "  ✗ io.lumnus.dbeaver.auth.openbao is NOT in the product assembly — refusing to build an"
  echo "    image that silently lacks the OpenBao auth model."
  exit 1
fi
echo "  ✓ backend, frontend, and the OpenBao auth bundle are all present"

step "assemble $OUT"
rm -rf "$OUT"
mkdir -p "$OUT"/{server,conf,workspace,web}
cp -rp "$BACKEND_PRODUCT"/* "$OUT/server"
cp -rp "$FRONTEND_LIB"/*    "$OUT/web"
cp -rp "$ROOT/config/core"/* "$OUT/conf"
cp -p  "$ROOT/config/GlobalConfiguration/.dbeaver/data-sources.json" "$OUT/conf/initial-data-sources.conf"
cp -p  ./scripts/* "$OUT/"
mkdir -p "$OUT/samples"

# JDBC drivers. Produced into deploy/drivers by the maven build; build-backend.sh MOVES them in as
# its last act. Creating an empty drivers/ instead is not a cosmetic miss — CloudBeaver's own
# internal store is H2, so the server dies at boot with ClassNotFoundException: org.h2.Driver
# before it ever serves a request. Verified 2026-07-31 by doing exactly that.
[ -d ./drivers ] || { echo "  ✗ deploy/drivers missing — run the maven build (--build)"; exit 1; }
cp -rp ./drivers "$OUT/drivers"
echo "  ✓ drivers: $(find "$OUT/drivers" -name '*.jar' | wc -l) jars"

step "generate cloudbeaver.conf"
# The server's main config is GENERATED, not checked in. Skipping this leaves the server without
# its top-level configuration.
if command -v mvn >/dev/null 2>&1; then
  mvn -B -q -f ../apps/config-generator compile exec:java -Dconfig.output="$OUT/conf/cloudbeaver.conf"
  echo "  ✓ conf/cloudbeaver.conf generated"
else
  echo "  ! maven unavailable — generating via container"
  docker run --rm -v "$ROOT/..:/ws" -v cb-m2:/root/.m2 -w /ws/cloudbeaver/deploy \
    maven:3.9-eclipse-temurin-21 \
    mvn -B -q -f ../apps/config-generator compile exec:java \
      -Dconfig.output="cloudbeaver/conf/cloudbeaver.conf"
  echo "  ✓ conf/cloudbeaver.conf generated (container)"
fi
[ -s "$OUT/conf/cloudbeaver.conf" ] || { echo "  ✗ cloudbeaver.conf empty/missing"; exit 1; }

echo
echo "[assemble] ready: $OUT"
echo "  docker build -f deploy/docker/Dockerfile -t registry.lab.lumnus.net/lumnus/cloudbeaver:<tag> deploy/"
