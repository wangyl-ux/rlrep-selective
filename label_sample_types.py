#!/usr/bin/env python3
import argparse
import json
import os
import re
import time
from collections import Counter

from evaluate_rlrep import (
    VULN_KEYS,
    classify_target_vulnerability,
    evaluate_original,
    get_fault_context,
    get_split_paths,
    write_csv,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Infer target vulnerability types for dataset samples and export labels for manual review.'
    )
    parser.add_argument('--dataset-path', default='dataset_vul/newALLBUGS')
    parser.add_argument('--split', default='validation')
    parser.add_argument('--detect-profile', default=os.environ.get('RLREP_DETECT_PROFILE', 'paper_default'))
    parser.add_argument('--detect-time-limit', type=int, default=60)
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


def infer_confidence(target_vuln, target_source, original_detect_ok, positive_types, fault_line_count):
    if target_vuln == 'UNRESOLVED':
        return 'low'
    if fault_line_count != 1:
        return 'low'

    high_sources = {
        'unique_detect',
        'fault_line_tx_origin',
        'external_call_detect_ed',
        'external_call_detect_re',
        'state_update_after_external_call',
    }
    medium_prefixes = (
        'external_call_ambiguous_prefers_',
        'max_detect_count',
    )
    medium_sources = {
        'fault_line_arithmetic',
        'fault_line_tod_keyword',
        'detect_prefers_tod',
    }
    low_sources = {
        'fault_line_external_call_only',
        'fault_line_tod_only',
        'unresolved',
    }

    if target_source in high_sources:
        return 'high'
    if target_source in low_sources:
        return 'low'
    if target_source in medium_sources:
        if target_source == 'fault_line_arithmetic' and original_detect_ok and 'IO' in positive_types:
            return 'high'
        return 'medium'
    if any(target_source.startswith(prefix) for prefix in medium_prefixes):
        if target_source == 'max_detect_count' and original_detect_ok and len(positive_types) == 1:
            return 'high'
        return 'medium'
    if not original_detect_ok:
        return 'low'
    return 'medium'


def needs_manual_review(row):
    if row['confidence'] != 'high':
        return 1
    if not row['original_detect_ok']:
        return 1
    if row['fault_line_count'] != 1:
        return 1
    return 0


def build_row(sample_name, contract_path, original_info):
    context = get_fault_context(contract_path)
    target_vuln, target_source, positive_types, fault_line = classify_target_vulnerability(
        contract_path,
        original_info['original_counts'],
        original_info['original_detect_ok'],
    )
    fault_line_count = get_fault_line_count(context['all_lines'])
    confidence = infer_confidence(
        target_vuln,
        target_source,
        original_info['original_detect_ok'],
        positive_types,
        fault_line_count,
    )

    row = {
        'sample_name': sample_name,
        'base_address': get_base_address(sample_name),
        'target_function': find_enclosing_function(context['all_lines'], context['bugline']),
        'target_vuln': target_vuln,
        'target_source': target_source,
        'confidence': confidence,
        'manual_review': 0,
        'fault_line_count': fault_line_count,
        'bugline': context['bugline'] + 1 if context['bugline'] >= 0 else 0,
        'fault_line': fault_line,
        'positive_detect_types': '|'.join(positive_types),
        'original_detect_ok': int(original_info['original_detect_ok']),
        'original_detect_status': original_info['original_detect_status'],
        'original_failed_tool': original_info['original_failed_tool'],
        'original_failed_reason': original_info['original_failed_reason'],
        'original_total': original_info['original_total'],
        'original_counts_json': counts_to_json(original_info['original_counts']),
    }
    row['manual_review'] = needs_manual_review(row)
    return row


def summarize(rows):
    type_counter = Counter(row['target_vuln'] for row in rows)
    source_counter = Counter(row['target_source'] for row in rows)
    confidence_counter = Counter(row['confidence'] for row in rows)
    manual_counter = Counter(row['manual_review'] for row in rows)

    type_rows = [{'target_vuln': key, 'count': value} for key, value in sorted(type_counter.items())]
    source_rows = [{'target_source': key, 'count': value} for key, value in sorted(source_counter.items())]
    confidence_rows = [{'confidence': key, 'count': value} for key, value in sorted(confidence_counter.items())]
    manual_rows = [
        {
            'manual_review': 'yes' if key else 'no',
            'count': value,
        }
        for key, value in sorted(manual_counter.items(), reverse=True)
    ]
    return type_rows, source_rows, confidence_rows, manual_rows


def print_summary(rows, type_rows, confidence_rows):
    print('sample_count={}'.format(len(rows)))
    print('target_vuln,count')
    for row in type_rows:
        print('{},{}'.format(row['target_vuln'], row['count']))
    print('confidence,count')
    for row in confidence_rows:
        print('{},{}'.format(row['confidence'], row['count']))
    review_count = sum(1 for row in rows if row['manual_review'])
    print('manual_review_count={}'.format(review_count))


def main():
    args = parse_args()
    os.environ['RLREP_DETECT_PROFILE'] = args.detect_profile

    dataset_path = os.path.abspath(args.dataset_path)
    contract_dir, _, _ = get_split_paths(dataset_path, args.split)
    if not os.path.isdir(contract_dir):
        raise FileNotFoundError('Contract directory not found: {}'.format(contract_dir))

    sample_names = sorted(name for name in os.listdir(contract_dir) if name.endswith('.sol'))
    if args.max_samples > 0:
        sample_names = sample_names[:args.max_samples]

    timestamp = time.strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.abspath(
        args.output_dir or os.path.join(dataset_path, 'eval', 'sample_labels_{}'.format(timestamp))
    )
    os.makedirs(output_dir, exist_ok=True)

    rows = []
    print(
        'label samples dataset={} split={} samples={} detect_profile={}'.format(
            dataset_path,
            args.split,
            len(sample_names),
            args.detect_profile,
        )
    )

    for index, filename in enumerate(sample_names, 1):
        sample_name = filename[:-4]
        contract_path = os.path.join(contract_dir, filename)
        original_info = evaluate_original(contract_path, args.detect_time_limit)
        row = build_row(sample_name, contract_path, original_info)
        rows.append(row)
        print(
            '[{}/{}] {} target={} source={} confidence={} review={}'.format(
                index,
                len(sample_names),
                sample_name,
                row['target_vuln'],
                row['target_source'],
                row['confidence'],
                row['manual_review'],
            )
        )

    manual_review_rows = [row for row in rows if row['manual_review']]
    type_rows, source_rows, confidence_rows, manual_rows = summarize(rows)

    label_fields = [
        'sample_name',
        'base_address',
        'target_function',
        'target_vuln',
        'target_source',
        'confidence',
        'manual_review',
        'fault_line_count',
        'bugline',
        'fault_line',
        'positive_detect_types',
        'original_detect_ok',
        'original_detect_status',
        'original_failed_tool',
        'original_failed_reason',
        'original_total',
        'original_counts_json',
    ]

    write_csv(os.path.join(output_dir, 'sample_type_labels.csv'), rows, label_fields)
    write_csv(os.path.join(output_dir, 'manual_review.csv'), manual_review_rows, label_fields)
    write_csv(os.path.join(output_dir, 'type_breakdown.csv'), type_rows, ['target_vuln', 'count'])
    write_csv(os.path.join(output_dir, 'source_breakdown.csv'), source_rows, ['target_source', 'count'])
    write_csv(os.path.join(output_dir, 'confidence_breakdown.csv'), confidence_rows, ['confidence', 'count'])
    write_csv(os.path.join(output_dir, 'manual_review_breakdown.csv'), manual_rows, ['manual_review', 'count'])

    with open(os.path.join(output_dir, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(
            {
                'dataset_path': dataset_path,
                'split': args.split,
                'detect_profile': args.detect_profile,
                'detect_time_limit': args.detect_time_limit,
                'sample_count': len(rows),
                'manual_review_count': len(manual_review_rows),
                'type_breakdown': type_rows,
                'source_breakdown': source_rows,
                'confidence_breakdown': confidence_rows,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print_summary(rows, type_rows, confidence_rows)
    print('output_dir={}'.format(output_dir))


if __name__ == '__main__':
    main()
