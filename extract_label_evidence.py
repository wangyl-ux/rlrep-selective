#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import time

from evaluate_rlrep import (
    VULN_KEYS,
    evaluate_original,
    get_fault_context,
    get_split_paths,
    has_recent_external_call,
    has_tx_origin_context,
    is_external_call_line,
    looks_like_arithmetic_issue,
    looks_like_state_update,
    looks_like_tod_line,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Extract per-sample labeling evidence without forcing final vulnerability labels.'
    )
    parser.add_argument('--dataset-path', default='dataset_vul/newALLBUGS')
    parser.add_argument('--split', default='validation')
    parser.add_argument('--detect-profiles', nargs='+', default=['paper_default', 'sailfish_tod'])
    parser.add_argument('--detect-time-limit', type=int, default=60)
    parser.add_argument('--continue-on-fail', action='store_true')
    parser.add_argument('--max-samples', type=int, default=0)
    parser.add_argument('--output-dir', default='')
    return parser.parse_args()


def get_base_address(sample_name):
    matched = re.match(r'^(.*)_\d+$', sample_name)
    if matched is not None:
        return matched.group(1)
    return sample_name


def counts_to_json(counts):
    return json.dumps({name: int(counts.get(name, 0)) for name in VULN_KEYS}, sort_keys=True)


def get_fault_line_count(lines):
    return sum(1 for line in lines if '// fault line' in line)


def find_enclosing_function(lines, bugline):
    if bugline < 0:
        return ''

    for index in range(bugline, -1, -1):
        stripped = lines[index].strip()
        if stripped.startswith('function '):
            name = stripped[len('function '):].split('(')[0].strip()
            return name or '<fallback>'
        if stripped.startswith('constructor(') or stripped.startswith('constructor '):
            return 'constructor'
        if stripped.startswith('modifier '):
            name = stripped[len('modifier '):].split('(')[0].strip()
            return 'modifier:' + name
        if re.match(r'^function\s*\(', stripped):
            return '<fallback>'
    return ''


def evaluate_with_profile(contract_path, detect_time_limit, detect_profile, continue_on_fail):
    previous_profile = os.environ.get('RLREP_DETECT_PROFILE')
    previous_continue = os.environ.get('RLREP_DETECT_CONTINUE_ON_FAIL')
    os.environ['RLREP_DETECT_PROFILE'] = detect_profile
    if continue_on_fail:
        os.environ['RLREP_DETECT_CONTINUE_ON_FAIL'] = '1'
    else:
        os.environ.pop('RLREP_DETECT_CONTINUE_ON_FAIL', None)
    try:
        return evaluate_original(contract_path, detect_time_limit)
    finally:
        if previous_profile is None:
            os.environ.pop('RLREP_DETECT_PROFILE', None)
        else:
            os.environ['RLREP_DETECT_PROFILE'] = previous_profile
        if previous_continue is None:
            os.environ.pop('RLREP_DETECT_CONTINUE_ON_FAIL', None)
        else:
            os.environ['RLREP_DETECT_CONTINUE_ON_FAIL'] = previous_continue


def make_profile_prefix(profile_name):
    return profile_name.replace('-', '_')


def build_row(sample_name, contract_path, profiles, detect_time_limit, continue_on_fail):
    context = get_fault_context(contract_path)
    fault_line = context['fault_line'].strip()
    row = {
        'sample_name': sample_name,
        'base_address': get_base_address(sample_name),
        'target_function': find_enclosing_function(context['all_lines'], context['bugline']),
        'fault_line_count': get_fault_line_count(context['all_lines']),
        'bugline': context['bugline'] + 1 if context['bugline'] >= 0 else 0,
        'fault_line': fault_line,
        'has_tx_origin_fault': int('tx.origin' in fault_line.lower()),
        'has_tx_origin_context': int(has_tx_origin_context(fault_line, context['prev_lines'], context['next_lines'])),
        'is_external_call_fault': int(is_external_call_line(fault_line)),
        'looks_like_arithmetic_fault': int(looks_like_arithmetic_issue(fault_line)),
        'looks_like_state_update_fault': int(looks_like_state_update(fault_line)),
        'has_recent_external_call_context': int(has_recent_external_call(context['prev_lines'])),
        'looks_like_tod_fault': int(looks_like_tod_line(fault_line)),
        'prev_lines_joined': ' || '.join(line.strip() for line in context['prev_lines']),
        'next_lines_joined': ' || '.join(line.strip() for line in context['next_lines']),
    }

    any_detect_ok = 0
    for profile_name in profiles:
        prefix = make_profile_prefix(profile_name)
        info = evaluate_with_profile(contract_path, detect_time_limit, profile_name, continue_on_fail)
        positive_types = [name for name in VULN_KEYS if info['original_counts'].get(name, 0) > 0]
        row[prefix + '_detect_ok'] = int(info['original_detect_ok'])
        row[prefix + '_detect_status'] = info['original_detect_status']
        row[prefix + '_failed_tool'] = info['original_failed_tool']
        row[prefix + '_failed_reason'] = info['original_failed_reason']
        row[prefix + '_total'] = info['original_total']
        row[prefix + '_counts_json'] = counts_to_json(info['original_counts'])
        row[prefix + '_positive_types'] = '|'.join(positive_types)
        row[prefix + '_unique_type'] = positive_types[0] if len(positive_types) == 1 else ''
        any_detect_ok = max(any_detect_ok, int(info['original_detect_ok']))

    row['any_detect_ok'] = any_detect_ok
    return row


def write_csv(path, rows, fieldnames):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    args = parse_args()
    dataset_path = os.path.abspath(args.dataset_path)
    contract_dir, _, _ = get_split_paths(dataset_path, args.split)
    if not os.path.isdir(contract_dir):
        raise FileNotFoundError('Contract directory not found: {}'.format(contract_dir))

    sample_names = sorted(name for name in os.listdir(contract_dir) if name.endswith('.sol'))
    if args.max_samples > 0:
        sample_names = sample_names[:args.max_samples]

    timestamp = time.strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.abspath(
        args.output_dir or os.path.join(dataset_path, 'eval', 'label_evidence_{}'.format(timestamp))
    )
    os.makedirs(output_dir, exist_ok=True)

    rows = []
    print(
        'extract label evidence dataset={} split={} samples={} detect_profiles={} continue_on_fail={}'.format(
            dataset_path,
            args.split,
            len(sample_names),
            ','.join(args.detect_profiles),
            int(args.continue_on_fail),
        )
    )

    for index, filename in enumerate(sample_names, 1):
        sample_name = filename[:-4]
        contract_path = os.path.join(contract_dir, filename)
        row = build_row(
            sample_name,
            contract_path,
            args.detect_profiles,
            args.detect_time_limit,
            args.continue_on_fail,
        )
        rows.append(row)
        print(
            '[{}/{}] {} tx={} ext={} arith={} tod_like={} any_detect_ok={}'.format(
                index,
                len(sample_names),
                sample_name,
                row['has_tx_origin_context'],
                row['is_external_call_fault'],
                row['looks_like_arithmetic_fault'],
                row['looks_like_tod_fault'],
                row['any_detect_ok'],
            )
        )

    base_fields = [
        'sample_name',
        'base_address',
        'target_function',
        'fault_line_count',
        'bugline',
        'fault_line',
        'has_tx_origin_fault',
        'has_tx_origin_context',
        'is_external_call_fault',
        'looks_like_arithmetic_fault',
        'looks_like_state_update_fault',
        'has_recent_external_call_context',
        'looks_like_tod_fault',
        'prev_lines_joined',
        'next_lines_joined',
        'any_detect_ok',
    ]
    profile_fields = []
    for profile_name in args.detect_profiles:
        prefix = make_profile_prefix(profile_name)
        profile_fields.extend([
            prefix + '_detect_ok',
            prefix + '_detect_status',
            prefix + '_failed_tool',
            prefix + '_failed_reason',
            prefix + '_total',
            prefix + '_counts_json',
            prefix + '_positive_types',
            prefix + '_unique_type',
        ])

    evidence_path = os.path.join(output_dir, 'sample_label_evidence.csv')
    write_csv(evidence_path, rows, base_fields + profile_fields)

    with open(os.path.join(output_dir, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(
            {
                'dataset_path': dataset_path,
                'split': args.split,
                'sample_count': len(rows),
                'detect_profiles': args.detect_profiles,
                'detect_time_limit': args.detect_time_limit,
                'continue_on_fail': args.continue_on_fail,
                'evidence_csv': evidence_path,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print('output_dir={}'.format(output_dir))


if __name__ == '__main__':
    main()
