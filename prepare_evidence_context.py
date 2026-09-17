#!/usr/bin/env python3
import argparse
import os

from preprocessing.context_config import DEFAULT_RULE_VERSION, DEFAULT_SLITHER_IMAGE, SUPPORTED_RULE_VERSIONS
from preprocessing.evidence_graph_context import prepare_evidence_context_directory


def split_paths(dataset_path, split_name):
    if split_name == "pretrain":
        return (
            os.path.join(dataset_path, "pretrain", "threelines-tokenseq"),
            os.path.join(dataset_path, "contract"),
        )
    if split_name == "train":
        return (
            os.path.join(dataset_path, "threelines-tokenseq"),
            os.path.join(dataset_path, "contract"),
        )
    return (
        os.path.join(dataset_path, split_name, "threelines-tokenseq"),
        os.path.join(dataset_path, split_name, "contract"),
    )


def parse_splits(values):
    result = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part and part not in result:
                result.append(part)
    return result


def parse_args():
    parser = argparse.ArgumentParser(
        description="Offline Slither evidence-graph context preparation for RLRep.")
    parser.add_argument("--dataset-path", required=True)
    parser.add_argument("--metadata-csv", default="")
    parser.add_argument("--splits", nargs="+", default=["pretrain", "train", "validation"])
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--max-samples", type=int, default=0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--slither-image", default=DEFAULT_SLITHER_IMAGE)
    parser.add_argument("--docker-timeout", type=float, default=120.0)
    parser.add_argument("--context-token-budget", type=int, default=64)
    parser.add_argument("--context-max-nodes", type=int, default=8)
    parser.add_argument("--context-max-hops", type=int, default=2)
    parser.add_argument("--context-fallback", choices=("selective_v1", "original"), default="selective_v1")
    parser.add_argument("--context-rule-version", choices=SUPPORTED_RULE_VERSIONS, default=DEFAULT_RULE_VERSION)
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.max_samples < 0:
        parser.error("--max-samples cannot be negative")
    if args.docker_timeout <= 0:
        parser.error("--docker-timeout must be positive")
    if args.context_token_budget < 1 or args.context_max_nodes < 1 or args.context_max_hops < 0:
        parser.error("context token/node budgets must be positive and max hops cannot be negative")
    return args


def main():
    args = parse_args()
    dataset_path = os.path.abspath(args.dataset_path)
    for split_name in parse_splits(args.splits):
        original_dir, contract_dir = split_paths(dataset_path, split_name)
        for required in (original_dir, contract_dir):
            if not os.path.isdir(required):
                raise FileNotFoundError("required {} path is missing: {}".format(split_name, required))
        prepare_evidence_context_directory(
            dataset_path, original_dir, contract_dir, split_name,
            metadata_csv=args.metadata_csv,
            workers=args.workers,
            max_samples=args.max_samples,
            force=args.force,
            slither_image=args.slither_image,
            docker_timeout=args.docker_timeout,
            context_token_budget=args.context_token_budget,
            context_max_nodes=args.context_max_nodes,
            context_max_hops=args.context_max_hops,
            context_fallback=args.context_fallback,
            context_rule_version=args.context_rule_version,
        )


if __name__ == "__main__":
    main()
