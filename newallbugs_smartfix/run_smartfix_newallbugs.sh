#!/usr/bin/env bash
set -euo pipefail

CORES="${1:-32}"
IMAGE="${SMARTFIX_IMAGE:-smartfix-newallbugs}"

docker run --rm -it \
  -v "$PWD/fix_result:/home/opam/fix_result" \
  -v "$PWD/newallbugs_smartfix/benchmarks:/home/opam/benchmarks:ro" \
  "$IMAGE" python3 fix_experiment/scripts/do_all_smartfix.py \
    --meta_csv /home/opam/benchmarks/mix-meta.csv \
    --dataset io,re,tx \
    --process "$CORES"
