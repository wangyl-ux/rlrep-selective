#!/usr/bin/env python3
import argparse
import csv
import json
import os
import time
from collections import defaultdict

from genetic import compile_ok
from smartBugs import VULN_KEYS, get_last_smart_details, smart


def parse_args():
    parser = argparse.ArgumentParser(
        description='Evaluate released repair_contract patches against validation originals.'
    )
    parser.add_argument('--dataset-path', default='dataset_vul/newALLBUGS')
    parser.add_argument('--split', default='validation')
    parser.add_argument('--repair-dir', default='')
    parser.add_argument(
        '--labels-csv',
        default='sample_label_assignment_20260524_continue/assistant_review_table6_repro_v1.csv',
    )
    parser.add_argument('--label-column', default='table6_repro_target_v1')
    parser.add_argument('--detect-time-limit', type=int, default=120)
    parser.add_argument('--detect-profile', default=os.environ.get('RLREP_DETECT_PROFILE', 'sailfish_tod'))
    parser.add_argument('--max-samples', type=int, default=0)
    parser.add_argument('--output-dir', default='')
    return parser.parse_args()


def get_split_contract_dir(dataset_path, split):
    split_root = os.path.join(dataset_path, split)
    if os.path.isdir(os.path.join(split_root, 'contract')):
        return os.path.join(split_root, 'contract')
    return os.path.join(split_root, 'contract')


def load_labels(labels_csv, label_column):
    labels = {}
    with open(labels_csv, 'r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if label_column not in (reader.fieldnames or []):
            raise KeyError('Label column not found in {}: {}'.format(labels_csv, label_column))
        for row in reader:
            sample_name = row.get('sample_name', '').strip()
            if not sample_name:
                continue
            labels[sample_name] = row[label_column].strip()
    return labels


def as_counts(detail):
    counts = {name: 0 for name in VULN_KEYS}
    if detail and detail.get('counts'):
        for name in VULN_KEYS:
            counts[name] = int(detail['counts'].get(name, 0))
    return counts


def counts_to_json(counts):
    return json.dumps({name: int(counts.get(name, 0)) for name in VULN_KEYS}, sort_keys=True)


def evaluate_contract(contract_path, detect_time_limit, use_cache):
    error = smart(contract_path, detect_time_limit, use_cache=use_cache)
    detail = get_last_smart_details()
    counts = as_counts(detail)
    return {
        'error': error,
        'detect_ok': int(error != -1),
        'counts': counts,
        'total': sum(counts.values()) if error != -1 else -1,
        'status': detail.get('status', '') if detail else '',
        'failed_tool': detail.get('failed_tool', '') if detail else '',
        'failed_reason': detail.get('failed_reason', '') if detail else '',
    }


def write_csv(path, rows, fieldnames):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def aggregate_summary(sample_rows):
    per_type = defaultdict(
        lambda: {
            'matched_sample_count': 0,
            'original_detect_ok_count': 0,
            'repair_compile_ok_count': 0,
            'repair_detect_ok_count': 0,
            'target_fixed_count': 0,
            'total_not_worse_count': 0,
            'weak_success_count': 0,
        }
    )

    for row in sample_rows:
        vuln_type = row['target_vuln']
        agg = per_type[vuln_type]
        agg['matched_sample_count'] += 1
        agg['original_detect_ok_count'] += int(row['original_detect_ok'])
        agg['repair_compile_ok_count'] += int(row['repair_compile_ok'])
        agg['repair_detect_ok_count'] += int(row['repair_detect_ok'])
        agg['target_fixed_count'] += int(row['target_fixed'])
        agg['total_not_worse_count'] += int(row['total_not_worse'])
        agg['weak_success_count'] += int(row['weak_success'])

    rows = []
    total = {
        'vuln_type': 'TOTAL',
        'matched_sample_count': 0,
        'original_detect_ok_count': 0,
        'repair_compile_ok_count': 0,
        'repair_detect_ok_count': 0,
        'target_fixed_count': 0,
        'total_not_worse_count': 0,
        'weak_success_count': 0,
        'weak_success_pct': 0.0,
    }
    ordered_types = [name for name in VULN_KEYS if name in per_type]
    extra_types = sorted(name for name in per_type if name not in ordered_types)
    for vuln_type in ordered_types + extra_types:
        agg = per_type[vuln_type]
        row = {
            'vuln_type': vuln_type,
            'matched_sample_count': agg['matched_sample_count'],
            'original_detect_ok_count': agg['original_detect_ok_count'],
            'repair_compile_ok_count': agg['repair_compile_ok_count'],
            'repair_detect_ok_count': agg['repair_detect_ok_count'],
            'target_fixed_count': agg['target_fixed_count'],
            'total_not_worse_count': agg['total_not_worse_count'],
            'weak_success_count': agg['weak_success_count'],
            'weak_success_pct': (
                agg['weak_success_count'] / agg['matched_sample_count'] if agg['matched_sample_count'] else 0.0
            ),
        }
        rows.append(row)
        for key in (
            'matched_sample_count',
            'original_detect_ok_count',
            'repair_compile_ok_count',
            'repair_detect_ok_count',
            'target_fixed_count',
            'total_not_worse_count',
            'weak_success_count',
        ):
            total[key] += row[key]
    total['weak_success_pct'] = (
        total['weak_success_count'] / total['matched_sample_count'] if total['matched_sample_count'] else 0.0
    )
    rows.append(total)
    return rows


def print_summary(summary_rows):
    print('vuln_type,matched,compile_ok,detect_ok,target_fixed,weak_success,weak_success_pct')
    for row in summary_rows:
        print(
            '{},{},{},{},{},{},{:.4f}'.format(
                row['vuln_type'],
                row['matched_sample_count'],
                row['repair_compile_ok_count'],
                row['repair_detect_ok_count'],
                row['target_fixed_count'],
                row['weak_success_count'],
                row['weak_success_pct'],
            )
        )


def main():
    args = parse_args()
    os.environ['RLREP_DETECT_PROFILE'] = args.detect_profile

    dataset_path = os.path.abspath(args.dataset_path)
    contract_dir = get_split_contract_dir(dataset_path, args.split)
    repair_dir = os.path.abspath(args.repair_dir or os.path.join(dataset_path, 'repair_contract'))
    labels_csv = os.path.abspath(args.labels_csv)

    if not os.path.isdir(contract_dir):
        raise FileNotFoundError('Validation contract directory not found: {}'.format(contract_dir))
    if not os.path.isdir(repair_dir):
        raise FileNotFoundError('Repair directory not found: {}'.format(repair_dir))
    if not os.path.isfile(labels_csv):
        raise FileNotFoundError('Labels CSV not found: {}'.format(labels_csv))

    validation_names = {name[:-4] for name in os.listdir(contract_dir) if name.endswith('.sol')}
    repair_names = sorted(name[:-4] for name in os.listdir(repair_dir) if name.endswith('.sol'))
    labels = load_labels(labels_csv, args.label_column)

    matched_names = [name for name in repair_names if name in validation_names]
    unmatched_names = [name for name in repair_names if name not in validation_names]

    if args.max_samples > 0:
        matched_names = matched_names[:args.max_samples]

    timestamp = time.strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.abspath(args.output_dir or os.path.join(dataset_path, 'eval', 'existing_repairs_eval_{}'.format(timestamp)))
    os.makedirs(output_dir, exist_ok=True)

    sample_rows = []
    skipped_rows = []

    print(
        'evaluate existing repairs dataset={} split={} matched={} unmatched={} detect_profile={}'.format(
            dataset_path,
            args.split,
            len(matched_names),
            len(unmatched_names),
            args.detect_profile,
        )
    )

    for index, sample_name in enumerate(matched_names, 1):
        target_vuln = labels.get(sample_name, '')
        original_path = os.path.join(contract_dir, sample_name + '.sol')
        repair_path = os.path.join(repair_dir, sample_name + '.sol')

        original_info = evaluate_contract(original_path, args.detect_time_limit, use_cache=True)
        repair_compile_ok = int(compile_ok(repair_path))

        repair_info = {
            'error': -1,
            'detect_ok': 0,
            'counts': {name: 0 for name in VULN_KEYS},
            'total': -1,
            'status': '',
            'failed_tool': '',
            'failed_reason': '',
        }
        if repair_compile_ok:
            repair_info = evaluate_contract(repair_path, args.detect_time_limit, use_cache=False)

        target_fixed = 0
        if target_vuln in VULN_KEYS and repair_info['detect_ok']:
            target_fixed = int(repair_info['counts'].get(target_vuln, 0) == 0)
        total_not_worse = 0
        if original_info['detect_ok'] and repair_info['detect_ok']:
            total_not_worse = int(repair_info['total'] <= original_info['total'])
        weak_success = int(target_fixed and total_not_worse)

        row = {
            'sample_name': sample_name,
            'target_vuln': target_vuln or 'UNLABELED',
            'original_path': original_path,
            'repair_path': repair_path,
            'original_detect_ok': original_info['detect_ok'],
            'original_error': original_info['error'],
            'original_total': original_info['total'],
            'original_detect_status': original_info['status'],
            'original_failed_tool': original_info['failed_tool'],
            'original_failed_reason': original_info['failed_reason'],
            'original_counts_json': counts_to_json(original_info['counts']),
            'repair_compile_ok': repair_compile_ok,
            'repair_detect_ok': repair_info['detect_ok'],
            'repair_error': repair_info['error'],
            'repair_total': repair_info['total'],
            'repair_detect_status': repair_info['status'],
            'repair_failed_tool': repair_info['failed_tool'],
            'repair_failed_reason': repair_info['failed_reason'],
            'repair_counts_json': counts_to_json(repair_info['counts']),
            'target_fixed': target_fixed,
            'total_not_worse': total_not_worse,
            'weak_success': weak_success,
        }
        sample_rows.append(row)
        print(
            '[{}/{}] {} target={} compile={} detect={} weak_success={}'.format(
                index,
                len(matched_names),
                sample_name,
                row['target_vuln'],
                row['repair_compile_ok'],
                row['repair_detect_ok'],
                row['weak_success'],
            )
        )

    for sample_name in unmatched_names:
        skipped_rows.append(
            {
                'sample_name': sample_name,
                'reason': 'repair_contract_not_in_validation_split',
            }
        )

    summary_rows = aggregate_summary(sample_rows)

    sample_fields = [
        'sample_name',
        'target_vuln',
        'original_path',
        'repair_path',
        'original_detect_ok',
        'original_error',
        'original_total',
        'original_detect_status',
        'original_failed_tool',
        'original_failed_reason',
        'original_counts_json',
        'repair_compile_ok',
        'repair_detect_ok',
        'repair_error',
        'repair_total',
        'repair_detect_status',
        'repair_failed_tool',
        'repair_failed_reason',
        'repair_counts_json',
        'target_fixed',
        'total_not_worse',
        'weak_success',
    ]
    summary_fields = [
        'vuln_type',
        'matched_sample_count',
        'original_detect_ok_count',
        'repair_compile_ok_count',
        'repair_detect_ok_count',
        'target_fixed_count',
        'total_not_worse_count',
        'weak_success_count',
        'weak_success_pct',
    ]

    write_csv(os.path.join(output_dir, 'samples.csv'), sample_rows, sample_fields)
    write_csv(os.path.join(output_dir, 'summary.csv'), summary_rows, summary_fields)
    write_csv(os.path.join(output_dir, 'unmatched_repairs.csv'), skipped_rows, ['sample_name', 'reason'])

    with open(os.path.join(output_dir, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(
            {
                'dataset_path': dataset_path,
                'split': args.split,
                'repair_dir': repair_dir,
                'labels_csv': labels_csv,
                'label_column': args.label_column,
                'detect_profile': args.detect_profile,
                'detect_time_limit': args.detect_time_limit,
                'repair_file_count': len(repair_names),
                'matched_validation_count': len(matched_names),
                'unmatched_repair_count': len(unmatched_names),
                'summary': summary_rows,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print_summary(summary_rows)
    print('output_dir={}'.format(output_dir))


if __name__ == '__main__':
    main()
