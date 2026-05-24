#!/usr/bin/env python3
import argparse
import json
import os
import re
import time
from collections import Counter

from evaluate_rlrep import (
    VULN_KEYS,
    choose_by_max_count,
    classify_target_vulnerability,
    evaluate_original,
    get_fault_context,
    get_split_paths,
    has_recent_external_call,
    has_tx_origin_context,
    is_external_call_line,
    looks_like_arithmetic_issue,
    looks_like_state_update,
    looks_like_tod_line,
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
    parser.add_argument('--tod-supplement-profile', default='sailfish_tod')
    parser.add_argument('--disable-tod-supplement', action='store_true')
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
        'fault_context_tx_origin',
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
        'tod_supplement_sailfish',
    }
    low_sources = {
        'partial_external_call_only',
        'partial_state_update_after_external_call',
        'partial_arithmetic_only',
        'partial_tod_only',
        'fault_line_tod_only',
        'unresolved',
    }

    if target_source.startswith('partial_'):
        return 'low'
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


def derive_benchmark_label(row, context, positive_types, original_counts, original_detect_ok):
    strict_vuln = row['strict_target_vuln']
    strict_source = row['strict_target_source']
    strict_confidence = row['strict_confidence']
    fault_line = row['fault_line']

    if strict_vuln != 'UNRESOLVED':
        if (
            row.get('tod_supplement_seen_tod')
            and strict_vuln in ('ED', 'RE', 'IO')
            and (
                row['main_target_source'].startswith('partial_')
                or row['main_target_source'] in ('detect_prefers_tod', 'fault_line_tod_keyword', 'fault_line_tod_only')
                or looks_like_tod_line(fault_line)
            )
        ):
            return 'TOD', 'benchmark_tod_family_from_supplement', 'medium'
        if strict_confidence == 'high':
            return strict_vuln, 'strict_passthrough', 'high'
        return strict_vuln, 'strict_passthrough', 'medium'

    if has_tx_origin_context(fault_line, context['prev_lines'], context['next_lines']):
        return 'TX', 'benchmark_tx_origin_context', 'high'

    if row.get('tod_supplement_seen_tod'):
        if looks_like_tod_line(fault_line) or 'TOD' in positive_types:
            return 'TOD', 'benchmark_tod_supplement_supported', 'medium'
        return 'TOD', 'benchmark_tod_supplement_only', 'low'

    if 'TOD' in positive_types and looks_like_tod_line(fault_line):
        return 'TOD', 'benchmark_tod_detect_supported', 'medium'

    if 'TOD' in positive_types:
        return 'TOD', 'benchmark_tod_detect_only', 'low'

    if is_external_call_line(fault_line):
        if 'RE' in positive_types or has_recent_external_call(context['prev_lines']):
            return 'RE', 'benchmark_external_call_re_guess', 'low'
        return 'ED', 'benchmark_external_call_ed_guess', 'low'

    if looks_like_state_update(fault_line) and has_recent_external_call(context['prev_lines']):
        return 'RE', 'benchmark_state_update_after_external_call', 'low'

    if looks_like_arithmetic_issue(fault_line):
        return 'IO', 'benchmark_arithmetic_guess', 'low'

    if looks_like_tod_line(fault_line):
        return 'TOD', 'benchmark_tod_syntax_guess', 'low'

    if original_detect_ok:
        target, tie_types = choose_by_max_count(original_counts, preferred_order=('TOD', 'RE', 'ED', 'IO', 'TX'))
        if target:
            if len(tie_types) == 1:
                return target, 'benchmark_max_detect_count', 'low'
            return target, 'benchmark_max_detect_count_tie={}'.format('|'.join(tie_types)), 'low'

    return 'UNRESOLVED', 'benchmark_unresolved', 'low'


def derive_manual_review(row):
    reasons = []

    if row['fault_line_count'] != 1:
        reasons.append('multiple_fault_lines')
    if not row['original_detect_ok']:
        reasons.append('detector_incomplete')
    if row['strict_confidence'] != 'high':
        reasons.append('strict_confidence_{}'.format(row['strict_confidence']))
    if row['strict_target_vuln'] == 'UNRESOLVED':
        reasons.append('strict_unresolved')
    if row['benchmark_confidence'] != 'high':
        reasons.append('benchmark_confidence_{}'.format(row['benchmark_confidence']))
    if row['benchmark_target_vuln'] == 'UNRESOLVED':
        reasons.append('benchmark_unresolved')
    if row['benchmark_target_vuln'] != row['strict_target_vuln']:
        reasons.append('benchmark_changed_family')
    if row.get('tod_supplement_seen_tod') and not row.get('tod_supplement_applied'):
        reasons.append('tod_signal_conflict')

    high_priority = {
        'multiple_fault_lines',
        'strict_unresolved',
        'benchmark_unresolved',
        'tod_signal_conflict',
    }
    medium_priority = {
        'detector_incomplete',
        'benchmark_changed_family',
        'strict_confidence_medium',
        'strict_confidence_low',
        'benchmark_confidence_medium',
        'benchmark_confidence_low',
    }

    if any(reason in high_priority for reason in reasons):
        priority = 'high'
    elif any(reason in medium_priority for reason in reasons):
        priority = 'medium'
    else:
        priority = 'low'

    return {
        'manual_review': int(bool(reasons)),
        'manual_reason_codes': '|'.join(reasons),
        'review_priority': priority,
    }


def evaluate_original_with_profile(contract_path, detect_time_limit, detect_profile):
    previous_profile = os.environ.get('RLREP_DETECT_PROFILE')
    os.environ['RLREP_DETECT_PROFILE'] = detect_profile
    try:
        return evaluate_original(contract_path, detect_time_limit)
    finally:
        if previous_profile is None:
            os.environ.pop('RLREP_DETECT_PROFILE', None)
        else:
            os.environ['RLREP_DETECT_PROFILE'] = previous_profile


def should_run_tod_supplement(row, positive_types, original_info, tod_supplement_profile):
    if not tod_supplement_profile:
        return False
    if row['target_vuln'] == 'TOD' and row['confidence'] == 'high':
        return False
    if original_info['original_failed_tool'] == 'securify':
        return True
    if 'TOD' in positive_types:
        return True
    if looks_like_tod_line(row['fault_line']):
        return True
    if row['target_vuln'] == 'UNRESOLVED':
        return True
    return False


def should_override_with_tod(row):
    source = row['target_source']
    target = row['target_vuln']

    if target == 'UNRESOLVED':
        return True, 'main_unresolved'
    if source.startswith('partial_'):
        return True, 'main_partial'
    if source in ('detect_prefers_tod', 'fault_line_tod_keyword', 'fault_line_tod_only'):
        return True, 'main_tod_leaning'
    if source.startswith('max_detect_count_tie=') and 'TOD' in source:
        return True, 'main_tie_includes_tod'
    if target == 'TOD':
        return False, 'already_tod'
    return False, 'strong_non_tod_main_label'


def apply_tod_supplement(row, contract_path, positive_types, original_info, detect_time_limit, tod_supplement_profile):
    row['main_target_vuln'] = row['target_vuln']
    row['main_target_source'] = row['target_source']
    row['main_confidence'] = row['confidence']
    row['tod_supplement_profile'] = tod_supplement_profile or ''
    row['tod_supplement_requested'] = 0
    row['tod_supplement_detect_ok'] = 0
    row['tod_supplement_detect_status'] = ''
    row['tod_supplement_counts_json'] = ''
    row['tod_supplement_positive_types'] = ''
    row['tod_supplement_failed_tool'] = ''
    row['tod_supplement_failed_reason'] = ''
    row['tod_supplement_tod_count'] = 0
    row['tod_supplement_seen_tod'] = 0
    row['tod_supplement_override_allowed'] = 0
    row['tod_supplement_override_reason'] = ''
    row['tod_supplement_applied'] = 0
    row['tod_supplement_conflict'] = 0

    if not should_run_tod_supplement(row, positive_types, original_info, tod_supplement_profile):
        return row

    row['tod_supplement_requested'] = 1
    supplement_info = evaluate_original_with_profile(contract_path, detect_time_limit, tod_supplement_profile)
    row['tod_supplement_detect_ok'] = int(supplement_info['original_detect_ok'])
    row['tod_supplement_detect_status'] = supplement_info['original_detect_status']
    row['tod_supplement_counts_json'] = counts_to_json(supplement_info['original_counts'])
    row['tod_supplement_positive_types'] = '|'.join(
        name for name in VULN_KEYS if supplement_info['original_counts'].get(name, 0) > 0
    )
    row['tod_supplement_failed_tool'] = supplement_info['original_failed_tool']
    row['tod_supplement_failed_reason'] = supplement_info['original_failed_reason']
    row['tod_supplement_tod_count'] = int(supplement_info['original_counts'].get('TOD', 0))

    override_allowed, override_reason = should_override_with_tod(row)
    row['tod_supplement_override_allowed'] = int(override_allowed)
    row['tod_supplement_override_reason'] = override_reason

    if supplement_info['original_detect_ok'] and row['tod_supplement_tod_count'] > 0:
        row['tod_supplement_seen_tod'] = 1
        if override_allowed:
            row['target_vuln'] = 'TOD'
            row['target_source'] = 'tod_supplement_sailfish'
            row['confidence'] = 'medium'
            row['tod_supplement_applied'] = 1
        else:
            row['tod_supplement_conflict'] = 1
    return row


def build_row(sample_name, contract_path, original_info, detect_time_limit, tod_supplement_profile):
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
    row = apply_tod_supplement(
        row,
        contract_path,
        positive_types,
        original_info,
        detect_time_limit,
        tod_supplement_profile,
    )
    row['strict_target_vuln'] = row['target_vuln']
    row['strict_target_source'] = row['target_source']
    row['strict_confidence'] = row['confidence']

    benchmark_target_vuln, benchmark_target_source, benchmark_confidence = derive_benchmark_label(
        row,
        context,
        positive_types,
        original_info['original_counts'],
        original_info['original_detect_ok'],
    )
    row['benchmark_target_vuln'] = benchmark_target_vuln
    row['benchmark_target_source'] = benchmark_target_source
    row['benchmark_confidence'] = benchmark_confidence
    row['benchmark_target_changed'] = int(benchmark_target_vuln != row['strict_target_vuln'])

    review = derive_manual_review(row)
    row['manual_review'] = review['manual_review']
    row['manual_reason_codes'] = review['manual_reason_codes']
    row['review_priority'] = review['review_priority']
    return row


def summarize(rows):
    strict_type_counter = Counter(row['strict_target_vuln'] for row in rows)
    strict_source_counter = Counter(row['strict_target_source'] for row in rows)
    strict_confidence_counter = Counter(row['strict_confidence'] for row in rows)
    benchmark_type_counter = Counter(row['benchmark_target_vuln'] for row in rows)
    benchmark_source_counter = Counter(row['benchmark_target_source'] for row in rows)
    benchmark_confidence_counter = Counter(row['benchmark_confidence'] for row in rows)
    manual_counter = Counter(row['manual_review'] for row in rows)
    priority_counter = Counter(row['review_priority'] for row in rows)

    strict_type_rows = [{'target_vuln': key, 'count': value} for key, value in sorted(strict_type_counter.items())]
    strict_source_rows = [{'target_source': key, 'count': value} for key, value in sorted(strict_source_counter.items())]
    strict_confidence_rows = [{'confidence': key, 'count': value} for key, value in sorted(strict_confidence_counter.items())]
    benchmark_type_rows = [{'target_vuln': key, 'count': value} for key, value in sorted(benchmark_type_counter.items())]
    benchmark_source_rows = [{'target_source': key, 'count': value} for key, value in sorted(benchmark_source_counter.items())]
    benchmark_confidence_rows = [
        {'confidence': key, 'count': value} for key, value in sorted(benchmark_confidence_counter.items())
    ]
    manual_rows = [
        {
            'manual_review': 'yes' if key else 'no',
            'count': value,
        }
        for key, value in sorted(manual_counter.items(), reverse=True)
    ]
    priority_rows = [{'review_priority': key, 'count': value} for key, value in sorted(priority_counter.items())]
    return {
        'strict_type_rows': strict_type_rows,
        'strict_source_rows': strict_source_rows,
        'strict_confidence_rows': strict_confidence_rows,
        'benchmark_type_rows': benchmark_type_rows,
        'benchmark_source_rows': benchmark_source_rows,
        'benchmark_confidence_rows': benchmark_confidence_rows,
        'manual_rows': manual_rows,
        'priority_rows': priority_rows,
    }


def print_summary(rows, strict_type_rows, benchmark_type_rows, priority_rows):
    print('sample_count={}'.format(len(rows)))
    print('strict_target_vuln,count')
    for row in strict_type_rows:
        print('{},{}'.format(row['target_vuln'], row['count']))
    print('benchmark_target_vuln,count')
    for row in benchmark_type_rows:
        print('{},{}'.format(row['target_vuln'], row['count']))
    print('review_priority,count')
    for row in priority_rows:
        print('{},{}'.format(row['review_priority'], row['count']))
    review_count = sum(1 for row in rows if row['manual_review'])
    print('manual_review_count={}'.format(review_count))


def main():
    args = parse_args()
    os.environ['RLREP_DETECT_PROFILE'] = args.detect_profile
    tod_supplement_profile = '' if args.disable_tod_supplement else args.tod_supplement_profile

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
        row = build_row(
            sample_name,
            contract_path,
            original_info,
            args.detect_time_limit,
            tod_supplement_profile,
        )
        rows.append(row)
        print(
            '[{}/{}] {} main={} strict={} benchmark={} review={} priority={} tod_seen={} tod_override={}'.format(
                index,
                len(sample_names),
                sample_name,
                row['main_target_vuln'],
                row['strict_target_vuln'],
                row['benchmark_target_vuln'],
                row['manual_review'],
                row['review_priority'],
                row['tod_supplement_seen_tod'],
                row['tod_supplement_applied'],
            )
        )

    manual_review_rows = [row for row in rows if row['manual_review']]
    summaries = summarize(rows)

    label_fields = [
        'sample_name',
        'base_address',
        'target_function',
        'target_vuln',
        'target_source',
        'confidence',
        'main_target_vuln',
        'main_target_source',
        'main_confidence',
        'strict_target_vuln',
        'strict_target_source',
        'strict_confidence',
        'benchmark_target_vuln',
        'benchmark_target_source',
        'benchmark_confidence',
        'benchmark_target_changed',
        'manual_review',
        'manual_reason_codes',
        'review_priority',
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
        'tod_supplement_profile',
        'tod_supplement_requested',
        'tod_supplement_detect_ok',
        'tod_supplement_detect_status',
        'tod_supplement_counts_json',
        'tod_supplement_positive_types',
        'tod_supplement_failed_tool',
        'tod_supplement_failed_reason',
        'tod_supplement_tod_count',
        'tod_supplement_seen_tod',
        'tod_supplement_override_allowed',
        'tod_supplement_override_reason',
        'tod_supplement_applied',
        'tod_supplement_conflict',
    ]

    write_csv(os.path.join(output_dir, 'sample_type_labels.csv'), rows, label_fields)
    write_csv(os.path.join(output_dir, 'sample_type_labels_strict.csv'), rows, label_fields)
    write_csv(os.path.join(output_dir, 'sample_type_labels_benchmark.csv'), rows, label_fields)
    write_csv(os.path.join(output_dir, 'manual_review.csv'), manual_review_rows, label_fields)
    write_csv(os.path.join(output_dir, 'manual_review_queue.csv'), manual_review_rows, label_fields)
    write_csv(os.path.join(output_dir, 'type_breakdown.csv'), summaries['strict_type_rows'], ['target_vuln', 'count'])
    write_csv(os.path.join(output_dir, 'source_breakdown.csv'), summaries['strict_source_rows'], ['target_source', 'count'])
    write_csv(
        os.path.join(output_dir, 'confidence_breakdown.csv'),
        summaries['strict_confidence_rows'],
        ['confidence', 'count'],
    )
    write_csv(os.path.join(output_dir, 'manual_review_breakdown.csv'), summaries['manual_rows'], ['manual_review', 'count'])
    write_csv(os.path.join(output_dir, 'strict_type_breakdown.csv'), summaries['strict_type_rows'], ['target_vuln', 'count'])
    write_csv(
        os.path.join(output_dir, 'strict_source_breakdown.csv'),
        summaries['strict_source_rows'],
        ['target_source', 'count'],
    )
    write_csv(
        os.path.join(output_dir, 'strict_confidence_breakdown.csv'),
        summaries['strict_confidence_rows'],
        ['confidence', 'count'],
    )
    write_csv(
        os.path.join(output_dir, 'benchmark_type_breakdown.csv'),
        summaries['benchmark_type_rows'],
        ['target_vuln', 'count'],
    )
    write_csv(
        os.path.join(output_dir, 'benchmark_source_breakdown.csv'),
        summaries['benchmark_source_rows'],
        ['target_source', 'count'],
    )
    write_csv(
        os.path.join(output_dir, 'benchmark_confidence_breakdown.csv'),
        summaries['benchmark_confidence_rows'],
        ['confidence', 'count'],
    )
    write_csv(
        os.path.join(output_dir, 'review_priority_breakdown.csv'),
        summaries['priority_rows'],
        ['review_priority', 'count'],
    )

    with open(os.path.join(output_dir, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(
            {
                'dataset_path': dataset_path,
                'split': args.split,
                'detect_profile': args.detect_profile,
                'tod_supplement_profile': tod_supplement_profile,
                'detect_time_limit': args.detect_time_limit,
                'sample_count': len(rows),
                'manual_review_count': len(manual_review_rows),
                'tod_supplement_requested_count': sum(int(row['tod_supplement_requested']) for row in rows),
                'tod_supplement_seen_tod_count': sum(int(row['tod_supplement_seen_tod']) for row in rows),
                'tod_supplement_applied_count': sum(int(row['tod_supplement_applied']) for row in rows),
                'tod_supplement_conflict_count': sum(int(row['tod_supplement_conflict']) for row in rows),
                'strict_type_breakdown': summaries['strict_type_rows'],
                'strict_source_breakdown': summaries['strict_source_rows'],
                'strict_confidence_breakdown': summaries['strict_confidence_rows'],
                'benchmark_type_breakdown': summaries['benchmark_type_rows'],
                'benchmark_source_breakdown': summaries['benchmark_source_rows'],
                'benchmark_confidence_breakdown': summaries['benchmark_confidence_rows'],
                'manual_review_breakdown': summaries['manual_rows'],
                'review_priority_breakdown': summaries['priority_rows'],
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print_summary(
        rows,
        summaries['strict_type_rows'],
        summaries['benchmark_type_rows'],
        summaries['priority_rows'],
    )
    print('output_dir={}'.format(output_dir))


if __name__ == '__main__':
    main()
