# newALLBUGS SmartFix Benchmark

Generated from:

- ../rlrep-vulnerability-aware-context/dataset_vul/newALLBUGS/eval/validation_vulnerability_type_final_labels_20260904.csv
- ../rlrep-vulnerability-aware-context/dataset_vul/newALLBUGS/validation/contract

This directory is an adapter for running the full SmartFix configuration on the
commonly supported vulnerability families only: IO, RE, and TX.

## Counts

- IO: 45
- RE: 10
- TX: 43
- Total supported: 98
- Skipped unsupported labels: 73
- Preparation issues: 0

## Run

From the SmartFix-Artifact directory on a Linux machine with Docker:

```bash
docker build -f Dockerfile.newallbugs -t smartfix-newallbugs --build-arg CORE=32 .

docker run --rm -it \
  -v "$PWD/fix_result:/home/opam/fix_result" \
  -v "$PWD/newallbugs_smartfix/benchmarks:/home/opam/benchmarks:ro" \
  smartfix-newallbugs python3 fix_experiment/scripts/do_all_smartfix.py \
    --meta_csv /home/opam/benchmarks/mix-meta.csv \
    --dataset io,re,tx \
    --process 32
```

Adjust `CORE` and `--process` to the number of CPU cores you want to use.
This uses the full SmartFix/Ours mode from the artifact, not Basic or Online
ablation variants.

If the server Docker daemon has a broken Docker Hub mirror and cannot pull
`ocaml/opam:ubuntu-20.04`, use an explicit registry mirror for the base image:

```bash
docker build -f Dockerfile.newallbugs -t smartfix-newallbugs \
  --build-arg CORE=32 \
  --build-arg BASE_IMAGE=docker.m.daocloud.io/ocaml/opam:ubuntu-20.04 .
```
