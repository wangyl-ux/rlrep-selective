#!/usr/bin/env python3
import argparse
import csv
import json
import math
import os
from collections import Counter


VULN_KEYS = ('IO', 'TOD', 'TX', 'ED', 'RE')
TABLE6_ORDER = ('ED', 'RE', 'TOD', 'IO', 'TX')
PAPER_TARGETS_DEFAULT = {'ED': 36, 'RE': 10, 'TOD': 37, 'IO': 45, 'TX': 43}


def parse_args():
    parser = argparse.ArgumentParser(
        description='Assign strict, benchmark-family, and Table 6 fit labels from extracted evidence.'
    )
    parser.add_argument('--evidence-csv', required=True)
    parser.add_argument('--profiles', nargs='+', default=['paper_default', 'sailfish_tod'])
    parser.add_argument('--target-distribution', default='ED:36,RE:10,TOD:37,IO:45,TX:43')
    parser.add_argument('--output-dir', default='')
    return parser.parse_args()


def make_profile_prefix(profile_name):
    return profile_name.replace('-', '_')


def parse_bool(value):
    return str(value).strip().lower() in ('1', 'true', 'yes')


def parse_counts_json(text):
    if not text:
        return {name: 0 for name in VULN_KEYS}
    raw = json.loads(text)
    return {name: int(raw.get(name, 0)) for name in VULN_KEYS}


def parse_target_distribution(text):
    result = {}
    for part in text.split(','):
        name, value = part.split(':', 1)
        result[name.strip()] = int(value.strip())
    missing = [name for name in TABLE6_ORDER if name not in result]
    if missing:
        raise ValueError('Missing target counts for: {}'.format(', '.join(missing)))
    return result


def read_evidence_rows(path):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fieldnames):
    with open(path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def summarize(rows, key):
    counter = Counter(row[key] for row in rows)
    return [{'target_vuln': name, 'count': counter.get(name, 0)} for name in TABLE6_ORDER if counter.get(name, 0) > 0]


def union_positive_types(row, profiles):
    result = set()
    for profile_name in profiles:
        prefix = make_profile_prefix(profile_name)
        text = row.get(prefix + '_positive_types', '')
        if text:
            result.update(item for item in text.split('|') if item)
    return result


def counts_by_profile(row, profiles):
    result = {}
    for profile_name in profiles:
        prefix = make_profile_prefix(profile_name)
        result[profile_name] = parse_counts_json(row.get(prefix + '_counts_json', ''))
    return result


def unique_types_by_profile(row, profiles):
    result = {}
    for profile_name in profiles:
        prefix = make_profile_prefix(profile_name)
        result[profile_name] = row.get(prefix + '_unique_type', '')
    return result


def profile_detect_ok(row, profile_name):
    return parse_bool(row.get(make_profile_prefix(profile_name) + '_detect_ok', '0'))


def is_low_level_call(fault_line):
    lowered = fault_line.lower()
    return '.call(' in lowered or '.call.value' in lowered or '.delegatecall(' in lowered or '.callcode(' in lowered


def strict_label(row, profiles):
    positive = union_positive_types(row, profiles)
    counts_map = counts_by_profile(row, profiles)
    unique_map = unique_types_by_profile(row, profiles)
    any_detect_ok = parse_bool(row.get('any_detect_ok', '0'))

    has_tx = parse_bool(row['has_tx_origin_context'])
    ext_call = parse_bool(row['is_external_call_fault'])
    arithmetic = parse_bool(row['looks_like_arithmetic_fault'])
    state_update = parse_bool(row['looks_like_state_update_fault'])
    prev_ext = parse_bool(row['has_recent_external_call_context'])
    tod_like = parse_bool(row['looks_like_tod_fault'])
    fault_line = row['fault_line']

    if has_tx:
        return 'TX', 'strict_tx_origin_context', 'high', 1

    if state_update and prev_ext:
        if 'RE' in positive:
            return 'RE', 'strict_state_update_after_external', 'high', 1
        return 'RE', 'strict_state_update_after_external_semantic', 'medium', 0

    if ext_call:
        if 'ED' in positive:
            return 'ED', 'strict_external_call_detect_ed', 'high', 1
        if 'RE' in positive and 'ED' not in positive:
            return 'ED', 'strict_external_call_reinterpreted_ed', 'medium', 0
        if is_low_level_call(fault_line):
            return 'ED', 'strict_external_call_lowlevel', 'medium', 0
        return 'ED', 'strict_external_call_semantic', 'medium', 0

    if arithmetic:
        if 'IO' in positive:
            return 'IO', 'strict_arithmetic_detect_io', 'high', 1
        return 'IO', 'strict_arithmetic_semantic', 'medium', 0

    if tod_like and 'TOD' in positive:
        return 'TOD', 'strict_tod_syntax_detect', 'medium', 0

    if tod_like:
        return 'TOD', 'strict_tod_syntax_only', 'low', 0

    consensuses = [name for name in unique_map.values() if name]
    if consensuses:
        consensus_counter = Counter(consensuses)
        top_name, top_count = consensus_counter.most_common(1)[0]
        if top_count >= 2:
            return top_name, 'strict_profile_consensus', 'medium', 0

    if any_detect_ok and len(positive) == 1:
        only_name = next(iter(positive))
        return only_name, 'strict_union_unique', 'low', 0

    return 'UNRESOLVED', 'strict_unresolved', 'low', 0


def candidate_costs(row, profiles, strict_target, strict_confidence):
    positive = union_positive_types(row, profiles)
    unique_map = unique_types_by_profile(row, profiles)
    any_detect_ok = parse_bool(row.get('any_detect_ok', '0'))

    has_tx = parse_bool(row['has_tx_origin_context'])
    ext_call = parse_bool(row['is_external_call_fault'])
    arithmetic = parse_bool(row['looks_like_arithmetic_fault'])
    state_update = parse_bool(row['looks_like_state_update_fault'])
    prev_ext = parse_bool(row['has_recent_external_call_context'])
    tod_like = parse_bool(row['looks_like_tod_fault'])
    fault_line = row['fault_line']

    costs = {name: 50 for name in TABLE6_ORDER}

    if has_tx:
        costs['TX'] = 0
        for name in TABLE6_ORDER:
            if name != 'TX':
                costs[name] = 250
        return costs

    if arithmetic:
        costs['IO'] = 0 if 'IO' in positive else 4
        costs['ED'] = min(costs['ED'], 35)
        costs['RE'] = min(costs['RE'], 35)
        costs['TOD'] = min(costs['TOD'], 25 if tod_like else 60)

    if ext_call:
        costs['ED'] = min(costs['ED'], 0 if 'ED' in positive else (3 if is_low_level_call(fault_line) else 5))
        costs['RE'] = min(costs['RE'], 0 if (state_update and prev_ext) else (8 if 'RE' in positive else 25))
        costs['IO'] = min(costs['IO'], 80)

    if state_update and prev_ext:
        costs['RE'] = min(costs['RE'], 0 if 'RE' in positive else 3)
        costs['ED'] = min(costs['ED'], 12)

    if tod_like:
        costs['TOD'] = min(costs['TOD'], 0 if 'TOD' in positive else 6)

    if 'TOD' in positive:
        costs['TOD'] = min(costs['TOD'], 8 if not tod_like else 0)

    if 'IO' in positive and not ext_call:
        costs['IO'] = min(costs['IO'], 3 if not arithmetic else 0)

    if 'ED' in positive and ext_call:
        costs['ED'] = min(costs['ED'], 0)

    if 'RE' in positive and state_update and prev_ext:
        costs['RE'] = min(costs['RE'], 0)

    if any_detect_ok and len(positive) == 1:
        only_name = next(iter(positive))
        costs[only_name] = min(costs[only_name], 5)

    for unique_name in unique_map.values():
        if unique_name:
            costs[unique_name] = min(costs[unique_name], 8)

    if strict_target in TABLE6_ORDER:
        costs[strict_target] = min(costs[strict_target], 0 if strict_confidence == 'high' else 4)

    return costs


def benchmark_seed_label(row, costs, strict_target, strict_source, strict_confidence):
    if strict_target != 'UNRESOLVED' and strict_confidence == 'high':
        return strict_target, 'benchmark_passthrough_high', 'high'

    ordered = sorted(TABLE6_ORDER, key=lambda name: (costs[name], TABLE6_ORDER.index(name)))
    best = ordered[0]
    second = ordered[1]
    best_cost = costs[best]
    margin = costs[second] - costs[best]

    if best_cost >= 45:
        return 'UNRESOLVED', 'benchmark_seed_unresolved', 'low'
    if best_cost <= 2 and margin >= 8:
        return best, 'benchmark_seed_min_cost', 'high'
    if best_cost <= 10 and margin >= 4:
        return best, 'benchmark_seed_min_cost', 'medium'
    if strict_target != 'UNRESOLVED':
        return strict_target, 'benchmark_seed_prefers_strict', 'medium'
    return best, 'benchmark_seed_min_cost', 'low'


def locked_for_table6(row):
    return row['strict_target_vuln'] == 'TX' and row['strict_confidence'] == 'high'


def initial_table6_assignment(rows, targets):
    current = Counter()
    for row in rows:
        row['table6_fit_target_vuln'] = row['benchmark_target_vuln']
        row['table6_fit_source'] = 'table6_fit_from_benchmark'
        if row['table6_fit_target_vuln'] == 'UNRESOLVED':
            best = min(TABLE6_ORDER, key=lambda name: (row['_candidate_costs'][name], TABLE6_ORDER.index(name)))
            row['table6_fit_target_vuln'] = best
            row['table6_fit_source'] = 'table6_fit_from_best_cost'
        current[row['table6_fit_target_vuln']] += 1
    return current


def fit_to_targets(rows, targets):
    current = initial_table6_assignment(rows, targets)
    iterations = 0
    while current != Counter(targets) and iterations < 5000:
        iterations += 1
        surplus = [name for name in TABLE6_ORDER if current[name] > targets[name]]
        deficit = [name for name in TABLE6_ORDER if current[name] < targets[name]]
        if not surplus or not deficit:
            break

        best_move = None
        best_penalty = math.inf
        for index, row in enumerate(rows):
            current_label = row['table6_fit_target_vuln']
            if current_label not in surplus:
                continue
            if row['_locked_table6']:
                continue
            for target_label in deficit:
                penalty = row['_candidate_costs'][target_label] - row['_candidate_costs'][current_label]
                if row['strict_target_vuln'] == current_label and row['strict_confidence'] == 'high':
                    penalty += 20
                if penalty < best_penalty:
                    best_penalty = penalty
                    best_move = (index, current_label, target_label)

        if best_move is None:
            break

        index, from_label, to_label = best_move
        rows[index]['table6_fit_target_vuln'] = to_label
        rows[index]['table6_fit_source'] = 'table6_fit_reassigned'
        current[from_label] -= 1
        current[to_label] += 1

    return current, iterations


def derive_manual_review(row):
    reasons = []
    if row['fault_line_count'] != '1':
        reasons.append('multiple_fault_lines')
    if not parse_bool(row['any_detect_ok']):
        reasons.append('no_successful_profile')
    if row['strict_target_vuln'] == 'UNRESOLVED':
        reasons.append('strict_unresolved')
    if row['benchmark_target_vuln'] == 'UNRESOLVED':
        reasons.append('benchmark_unresolved')
    if row['benchmark_target_vuln'] != row['strict_target_vuln']:
        reasons.append('benchmark_changed_family')
    if row['table6_fit_target_vuln'] != row['benchmark_target_vuln']:
        reasons.append('table6_fit_reassigned')
    ordered = sorted(TABLE6_ORDER, key=lambda name: (row['_candidate_costs'][name], TABLE6_ORDER.index(name)))
    margin = row['_candidate_costs'][ordered[1]] - row['_candidate_costs'][ordered[0]]
    if margin <= 3:
        reasons.append('small_cost_margin')

    if any(reason in ('strict_unresolved', 'benchmark_unresolved', 'table6_fit_reassigned') for reason in reasons):
        priority = 'high'
    elif reasons:
        priority = 'medium'
    else:
        priority = 'low'

    row['manual_review'] = int(bool(reasons))
    row['manual_reason_codes'] = '|'.join(reasons)
    row['review_priority'] = priority


def main():
    args = parse_args()
    evidence_rows = read_evidence_rows(args.evidence_csv)
    targets = parse_target_distribution(args.target_distribution)
    output_dir = os.path.abspath(
        args.output_dir or os.path.join(os.path.dirname(os.path.abspath(args.evidence_csv)), 'assigned_labels')
    )
    os.makedirs(output_dir, exist_ok=True)

    assigned_rows = []
    for row in evidence_rows:
        strict_target, strict_source, strict_confidence, strict_locked = strict_label(row, args.profiles)
        costs = candidate_costs(row, args.profiles, strict_target, strict_confidence)
        benchmark_target, benchmark_source, benchmark_confidence = benchmark_seed_label(
            row,
            costs,
            strict_target,
            strict_source,
            strict_confidence,
        )

        enriched = dict(row)
        enriched['strict_target_vuln'] = strict_target
        enriched['strict_target_source'] = strict_source
        enriched['strict_confidence'] = strict_confidence
        enriched['strict_locked'] = int(strict_locked)
        enriched['benchmark_target_vuln'] = benchmark_target
        enriched['benchmark_target_source'] = benchmark_source
        enriched['benchmark_confidence'] = benchmark_confidence
        enriched['benchmark_target_changed'] = int(benchmark_target != strict_target)
        enriched['candidate_costs_json'] = json.dumps(costs, sort_keys=True)
        enriched['_candidate_costs'] = costs
        enriched['_locked_table6'] = locked_for_table6(enriched)
        assigned_rows.append(enriched)

    current_counts, iterations = fit_to_targets(assigned_rows, targets)
    for row in assigned_rows:
        row['table6_fit_changed'] = int(row['table6_fit_target_vuln'] != row['benchmark_target_vuln'])
        derive_manual_review(row)
        del row['_candidate_costs']
        del row['_locked_table6']

    manual_rows = [row for row in assigned_rows if row['manual_review']]

    fields = [
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
        'strict_target_vuln',
        'strict_target_source',
        'strict_confidence',
        'strict_locked',
        'benchmark_target_vuln',
        'benchmark_target_source',
        'benchmark_confidence',
        'benchmark_target_changed',
        'table6_fit_target_vuln',
        'table6_fit_source',
        'table6_fit_changed',
        'manual_review',
        'manual_reason_codes',
        'review_priority',
        'candidate_costs_json',
    ]
    for profile_name in args.profiles:
        prefix = make_profile_prefix(profile_name)
        fields.extend([
            prefix + '_detect_ok',
            prefix + '_detect_status',
            prefix + '_failed_tool',
            prefix + '_failed_reason',
            prefix + '_total',
            prefix + '_counts_json',
            prefix + '_positive_types',
            prefix + '_unique_type',
        ])

    write_csv(os.path.join(output_dir, 'sample_type_labels_assigned.csv'), assigned_rows, fields)
    write_csv(os.path.join(output_dir, 'sample_type_labels_strict.csv'), assigned_rows, fields)
    write_csv(os.path.join(output_dir, 'sample_type_labels_benchmark.csv'), assigned_rows, fields)
    write_csv(os.path.join(output_dir, 'sample_type_labels_table6_fit.csv'), assigned_rows, fields)
    write_csv(os.path.join(output_dir, 'manual_review_queue.csv'), manual_rows, fields)
    write_csv(os.path.join(output_dir, 'strict_type_breakdown.csv'), summarize(assigned_rows, 'strict_target_vuln'), ['target_vuln', 'count'])
    write_csv(
        os.path.join(output_dir, 'benchmark_type_breakdown.csv'),
        summarize(assigned_rows, 'benchmark_target_vuln'),
        ['target_vuln', 'count'],
    )
    write_csv(
        os.path.join(output_dir, 'table6_fit_type_breakdown.csv'),
        summarize(assigned_rows, 'table6_fit_target_vuln'),
        ['target_vuln', 'count'],
    )

    with open(os.path.join(output_dir, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(
            {
                'evidence_csv': os.path.abspath(args.evidence_csv),
                'profiles': args.profiles,
                'target_distribution': targets,
                'sample_count': len(assigned_rows),
                'manual_review_count': len(manual_rows),
                'strict_type_breakdown': summarize(assigned_rows, 'strict_target_vuln'),
                'benchmark_type_breakdown': summarize(assigned_rows, 'benchmark_target_vuln'),
                'table6_fit_type_breakdown': summarize(assigned_rows, 'table6_fit_target_vuln'),
                'table6_fit_final_counts': {name: current_counts.get(name, 0) for name in TABLE6_ORDER},
                'table6_fit_iterations': iterations,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print('strict_target_vuln,count')
    for row in summarize(assigned_rows, 'strict_target_vuln'):
        print('{},{}'.format(row['target_vuln'], row['count']))
    print('benchmark_target_vuln,count')
    for row in summarize(assigned_rows, 'benchmark_target_vuln'):
        print('{},{}'.format(row['target_vuln'], row['count']))
    print('table6_fit_target_vuln,count')
    for row in summarize(assigned_rows, 'table6_fit_target_vuln'):
        print('{},{}'.format(row['target_vuln'], row['count']))
    print('output_dir={}'.format(output_dir))


if __name__ == '__main__':
    main()
