# LABELING_PROTOCOL

## Purpose

This repository now supports two complementary labeling views for RLRep samples in
`dataset_vul/newALLBUGS/validation`:

- `strict_semantic`: assign the vulnerability type that is most defensible from the
  local patch point, enclosing function, and nearby control/data-flow evidence.
- `benchmark_family`: assign the vulnerability family that best matches the paper-style
  benchmark grouping used for Table 6 style reporting.

The two views are intentionally different:

- `strict_semantic` prefers honesty and allows `UNRESOLVED`.
- `benchmark_family` is allowed to use broader family evidence, but low-certainty
  mappings are still sent to manual review.

## Core Principles

1. A sample is a repair instance, not a whole-contract label.
2. The `fault line` is a patch anchor, but not always the root-cause line.
3. Whole-contract detector counts are supporting evidence only; they do not by
   themselves determine the sample label.
4. `TX` and many `IO` cases are often local-semantic labels.
5. `RE` usually needs function-level ordering evidence.
6. `TOD` often needs cross-function or tool-derived dependency evidence.
7. Very uncertain samples should remain in the manual-review queue instead of being
   force-labeled automatically.

## Evidence Sources

Per sample, the labeling pipeline uses:

- `fault_line`
- enclosing function name
- previous and next context lines
- detector counts from the chosen profile
- detector completion status and failed tool
- optional TOD supplement evidence from `sailfish_tod`

## Strict Semantic Labeling Rules

The strict label is derived with the following priority:

1. `TX`
   - `tx.origin` appears in the fault line or immediate context.
2. `ED` / `RE`
   - external-call patterns are inspected before arithmetic.
   - unchecked/exception-disorder style external interactions prefer `ED`.
   - external interaction followed by state update prefers `RE`.
3. `IO`
   - arithmetic/state-update semantics with no stronger `TX/ED/RE` signal.
4. `TOD`
   - only when TOD-oriented syntax or tool evidence is present.
5. `UNRESOLVED`
   - conflicting or insufficient evidence.

`strict_semantic` may use TOD supplement evidence conservatively, but only when the
main label is weak enough to justify family escalation.

## Benchmark Family Labeling Rules

`benchmark_family` starts from the strict label and applies a broader family mapping:

- If the strict label is already strong and high-confidence, it normally passes through.
- `TOD` family can be selected when:
  - TOD supplement (`sailfish_tod`) reports TOD, and
  - the main strict evidence is weak/partial, or
  - the fault line already looks TOD-like.
- For strict `UNRESOLVED` samples, benchmark mapping may fall back to:
  - `TX` from `tx.origin` context
  - `ED` / `RE` from external-call behavior
  - `IO` from arithmetic behavior
  - `TOD` from supplement or strong TOD syntax

If evidence is still too weak, the benchmark candidate remains `UNRESOLVED` and is
queued for manual review.

## Manual Review Criteria

A sample is sent to manual review when any of the following is true:

- detector execution is incomplete
- the file contains multiple `fault line` markers
- the strict label confidence is not `high`
- the strict label is `UNRESOLVED`
- the benchmark label confidence is not `high`
- the benchmark label is `UNRESOLVED`
- the benchmark family differs from the strict label
- TOD supplement sees TOD but is not allowed to override the strict label

Recommended review priority:

- `high`
  - unresolved strict/benchmark label
  - multiple fault lines
  - TOD conflict signal
- `medium`
  - detector incomplete
  - benchmark family changed
  - medium/low confidence

## Output Files

`label_sample_types.py` now emits:

- `sample_type_labels.csv`
  - combined view with both strict and benchmark columns
- `sample_type_labels_strict.csv`
- `sample_type_labels_benchmark.csv`
- `manual_review_queue.csv`
- `strict_type_breakdown.csv`
- `benchmark_type_breakdown.csv`
- `review_priority_breakdown.csv`
- `summary.json`

Important columns:

- `strict_target_vuln`, `strict_target_source`, `strict_confidence`
- `benchmark_target_vuln`, `benchmark_target_source`, `benchmark_confidence`
- `manual_review`, `manual_reason_codes`, `review_priority`
- `tod_supplement_*`

## Recommended Usage

For semantic analysis and error analysis:

- use `strict_target_vuln`

For paper-facing benchmark reporting:

- start from `benchmark_target_vuln`
- manually review all rows in `manual_review_queue.csv`

For unstable detector settings:

- compare:
  - `paper_default`
  - `sailfish_tod`
  - `RLREP_DETECT_CONTINUE_ON_FAIL=1`

## Command Pattern

Example:

```bash
export RLREP_DETECT_PROFILE=paper_default
export RLREP_DETECT_CONTINUE_ON_FAIL=1
python label_sample_types.py --dataset-path dataset_vul/newALLBUGS --split validation
```
