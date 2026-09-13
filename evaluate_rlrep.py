#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import os
import pickle
import random
import re
import shutil
import time
from collections import Counter, defaultdict

from genetic import compile_ok
from main import Config_RL_multistep
from multistep_RLRep import Model
from preprocessing.selective_context import prepare_context_directory
from preprocessing.context_config import (
    DEFAULT_SLITHER_IMAGE,
    build_context_config,
    validate_checkpoint_context,
)
from smartBugs import VULN_KEYS, get_last_smart_details, smart
from utils2 import choose_action, get_action


EXTERNAL_CALL_MARKERS = ('.send(', '.transfer(', '.call.value', '.call(', '.delegatecall(', '.callcode(')
ARITHMETIC_MARKERS = ('+=', '-=', '*=', '/=', '++', '--', ' + ', ' - ', ' * ', ' / ')
CONTROL_MARKERS = ('if', 'require', 'assert', 'return', '=')


def parse_args():
    parser = argparse.ArgumentParser(
        description='Weak automatic evaluation for RLRep, approximating Table 6 with compile + detect checks.'
    )
    parser.add_argument('--dataset-path', default='dataset_vul/newALLBUGS')
    parser.add_argument('--split', default='validation')
    parser.add_argument('--model-name', default='multistep_RLRep')
    parser.add_argument('--model-path', default='')
    parser.add_argument('--beam-size', type=int, default=5)
    parser.add_argument('--detect-time-limit', type=int, default=60)
    parser.add_argument('--detect-profile', default=os.environ.get('RLREP_DETECT_PROFILE', 'paper_default'))
    parser.add_argument('--max-samples', type=int, default=0)
    parser.add_argument('--output-dir', default='')
    parser.add_argument(
        '--context-mode',
        '--context_mode',
        dest='context_mode',
        choices=('original', 'selective', 'selective_v1', 'evidence_graph'),
        default='original',
    )
    parser.add_argument(
        '--metadata-csv',
        '--metadata_csv',
        dest='metadata_csv',
        default='',
    )
    parser.add_argument('--context-token-budget', type=int, default=64)
    parser.add_argument('--context-max-nodes', type=int, default=8)
    parser.add_argument('--context-max-hops', type=int, default=2)
    parser.add_argument('--context-fallback', choices=('selective_v1', 'original'), default='selective_v1')
    parser.add_argument('--slither-image', default=DEFAULT_SLITHER_IMAGE)
    parser.add_argument(
        '--allow-legacy-context-checkpoint', action='store_true',
        help='explicitly allow an unverifiable legacy checkpoint with evidence_graph')
    args = parser.parse_args()
    if args.context_token_budget < 1 or args.context_max_nodes < 1 or args.context_max_hops < 0:
        parser.error('context token/node budgets must be positive and max hops cannot be negative')
    return args


def find_best_model_path(model_dir, model_name):
    best_epoch = -1
    best_path = ''
    pattern = re.compile(r'^{}_(\d+)$'.format(re.escape(model_name)))
    for name in os.listdir(model_dir):
        matched = pattern.match(name)
        if matched is None:
            continue
        epoch = int(matched.group(1))
        if epoch > best_epoch:
            best_epoch = epoch
            best_path = os.path.join(model_dir, name)
    return best_path, best_epoch


def load_vocab(dataset_path):
    with open(os.path.join(dataset_path, 'code_w2i.pkl'), 'rb') as f_code, open(
        os.path.join(dataset_path, 'ast_w2i.pkl'), 'rb'
    ) as f_ast:
        return pickle.load(f_code), pickle.load(f_ast)


def get_split_paths(dataset_path, split):
    split_root = os.path.join(dataset_path, split)
    if os.path.isdir(os.path.join(split_root, 'contract')):
        return (
            os.path.join(split_root, 'contract'),
            os.path.join(split_root, 'threelines-tokenseq'),
            os.path.join(split_root, 'ast'),
        )
    if split in ('train', 'root', 'full'):
        return (
            os.path.join(dataset_path, 'contract'),
            os.path.join(dataset_path, 'threelines-tokenseq'),
            os.path.join(dataset_path, 'ast'),
        )
    return (
        os.path.join(split_root, 'contract'),
        os.path.join(split_root, 'threelines-tokenseq'),
        os.path.join(split_root, 'ast'),
    )


def read_token_sequence(path):
    with open(path, 'r', encoding='utf-8') as f:
        return [token for token in f.read().split(' ') if token != '']


def encode_sequence(tokens, vocab, max_size):
    unk = vocab['<UNK>']
    return [vocab[token] if token in vocab else unk for token in tokens[:max_size]]


def load_sample_inputs(code_path, ast_path, code_w2i, ast_w2i, config):
    code_tokens = read_token_sequence(code_path)
    ast_tokens = read_token_sequence(ast_path)
    return (
        encode_sequence(code_tokens, code_w2i, config.MAX_INPUT_SIZE),
        encode_sequence(ast_tokens, ast_w2i, config.MAX_INPUT_SIZE),
    )


def get_fault_context(contract_path):
    with open(contract_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    bugline = -1
    for index, line in enumerate(lines):
        if '// fault line' in line:
            bugline = index
            break
    if bugline == -1:
        return {
            'bugline': -1,
            'fault_line': '',
            'prev_lines': [],
            'next_lines': [],
            'all_lines': lines,
        }
    fault_line = lines[bugline].split('// fault line')[0].rstrip()
    return {
        'bugline': bugline,
        'fault_line': fault_line,
        'prev_lines': lines[max(0, bugline - 3):bugline],
        'next_lines': lines[bugline + 1:bugline + 4],
        'all_lines': lines,
    }


def strip_spaces(text):
    return re.sub(r'\s+', ' ', text).strip()


def is_external_call_line(line):
    lowered = line.lower()
    return any(marker in lowered for marker in EXTERNAL_CALL_MARKERS)


def looks_like_arithmetic_issue(line):
    lowered = line.lower()
    if any(marker in lowered for marker in ARITHMETIC_MARKERS):
        return True
    return bool(re.search(r'\b(add|sub|mul|div)\b', lowered))


def looks_like_state_update(line):
    return any(marker in line for marker in ('=', '+=', '-=', '++', '--'))


def looks_like_tod_line(line):
    lowered = line.lower()
    keywords = (
        'approve',
        'allowance',
        'bid',
        'buy',
        'sell',
        'query',
        'set',
        'price',
        'payment',
        'gasprice',
    )
    return any(keyword in lowered for keyword in keywords)


def has_recent_external_call(prev_lines):
    prev_text = ' '.join(prev_lines).lower()
    return any(marker in prev_text for marker in EXTERNAL_CALL_MARKERS)


def has_tx_origin_context(fault_line, prev_lines, next_lines):
    context_text = ' '.join(prev_lines + [fault_line] + next_lines).lower()
    return 'tx.origin' in context_text


def choose_by_max_count(counts, preferred_order):
    max_count = max(counts.values()) if counts else 0
    if max_count <= 0:
        return '', []
    max_types = [name for name in VULN_KEYS if counts.get(name, 0) == max_count]
    for vuln_name in preferred_order:
        if vuln_name in max_types:
            return vuln_name, max_types
    return max_types[0], max_types


def classify_target_vulnerability(contract_path, original_counts, original_detect_ok):
    context = get_fault_context(contract_path)
    fault_line = strip_spaces(context['fault_line'])
    fault_lower = fault_line.lower()
    prev_lines = context['prev_lines']
    next_lines = context['next_lines']
    positive = [name for name in VULN_KEYS if original_counts.get(name, 0) > 0]

    if 'tx.origin' in fault_lower:
        return 'TX', 'fault_line_tx_origin', positive, fault_line

    if has_tx_origin_context(fault_line, prev_lines, next_lines):
        return 'TX', 'fault_context_tx_origin', positive, fault_line

    if is_external_call_line(fault_line):
        guarded = any(marker in fault_lower for marker in CONTROL_MARKERS)
        if 'ED' in positive and 'RE' not in positive:
            return 'ED', 'external_call_detect_ed', positive, fault_line
        if 'RE' in positive and 'ED' not in positive:
            return 'RE', 'external_call_detect_re', positive, fault_line
        if 'ED' in positive and 'RE' in positive:
            if guarded:
                return 'RE', 'external_call_ambiguous_prefers_re', positive, fault_line
            return 'ED', 'external_call_ambiguous_prefers_ed', positive, fault_line
        if not original_detect_ok:
            return 'ED', 'partial_external_call_only', positive, fault_line

    if 'RE' in positive and looks_like_state_update(fault_line) and has_recent_external_call(prev_lines):
        return 'RE', 'state_update_after_external_call', positive, fault_line

    if not original_detect_ok and looks_like_state_update(fault_line) and has_recent_external_call(prev_lines):
        return 'RE', 'partial_state_update_after_external_call', positive, fault_line

    if original_detect_ok and len(positive) == 1:
        return positive[0], 'unique_detect', positive, fault_line

    if looks_like_arithmetic_issue(fault_line) and 'IO' in positive:
        return 'IO', 'fault_line_arithmetic', positive, fault_line

    if not original_detect_ok and looks_like_arithmetic_issue(fault_line):
        return 'IO', 'partial_arithmetic_only', positive, fault_line

    if 'TOD' in positive and looks_like_tod_line(fault_line):
        return 'TOD', 'fault_line_tod_keyword', positive, fault_line

    if 'TOD' in positive and 'TX' not in positive and 'IO' not in positive:
        return 'TOD', 'detect_prefers_tod', positive, fault_line

    if original_detect_ok:
        target, tie_types = choose_by_max_count(original_counts, preferred_order=('TOD', 'RE', 'ED', 'IO', 'TX'))
        if target:
            if len(tie_types) == 1:
                return target, 'max_detect_count', positive, fault_line
            return target, 'max_detect_count_tie={}'.format('|'.join(tie_types)), positive, fault_line

    if looks_like_tod_line(fault_line):
        if original_detect_ok:
            return 'TOD', 'fault_line_tod_only', positive, fault_line
        return 'TOD', 'partial_tod_only', positive, fault_line

    return 'UNRESOLVED', 'unresolved', positive, fault_line


def stable_candidate_seed(sample_name, rank, action_ids):
    raw = '{}|{}|{}'.format(sample_name, rank, ','.join(str(x) for x in action_ids))
    return int(hashlib.sha1(raw.encode('utf-8')).hexdigest()[:8], 16)


def as_counts(detail):
    counts = {name: 0 for name in VULN_KEYS}
    if detail and detail.get('counts'):
        for name in VULN_KEYS:
            counts[name] = int(detail['counts'].get(name, 0))
    return counts


def counts_to_json(counts):
    return json.dumps({name: int(counts.get(name, 0)) for name in VULN_KEYS}, sort_keys=True)


def evaluate_original(contract_path, detect_time_limit):
    original_error = smart(contract_path, detect_time_limit, use_cache=True)
    original_detail = get_last_smart_details()
    original_counts = as_counts(original_detail)
    return {
        'original_error': original_error,
        'original_detail': original_detail,
        'original_counts': original_counts,
        'original_detect_ok': original_error != -1,
        'original_total': sum(original_counts.values()),
        'original_detect_status': original_detail.get('status', '') if original_detail else '',
        'original_failed_tool': original_detail.get('failed_tool', '') if original_detail else '',
        'original_failed_reason': original_detail.get('failed_reason', '') if original_detail else '',
    }


def apply_actions_for_candidate(contract_name, action_ids):
    result = choose_action(contract_name, action_ids, False, gitdif=True)
    repair_path = os.path.join('dataset_vul', 'newALLBUGS', 'repair_contract', contract_name + '.sol')
    return result == -99999, repair_path


def evaluate_candidate(
    sample_name,
    target_vuln,
    contract_path,
    candidate_dir,
    rank,
    action_ids,
    action_map,
    original_info,
    detect_time_limit,
):
    random.seed(stable_candidate_seed(sample_name, rank, action_ids))
    action_valid, repair_path = apply_actions_for_candidate(sample_name, action_ids)
    saved_path = os.path.join(candidate_dir, 'rank_{:02d}.sol'.format(rank))
    shutil.copyfile(repair_path, saved_path)

    result = {
        'sample_name': sample_name,
        'rank': rank,
        'candidate_path': saved_path,
        'action_ids': ' '.join(str(x) for x in action_ids),
        'action_names': ' || '.join(action_map[x] for x in action_ids) if action_ids else '',
        'action_len': len(action_ids),
        'action_valid': int(action_valid),
        'compile_ok': 0,
        'detect_ok': 0,
        'repair_error': -1,
        'repair_total': -1,
        'repair_counts': {name: 0 for name in VULN_KEYS},
        'target_fixed': 0,
        'total_not_worse': 0,
        'weak_success': 0,
        'repair_detect_status': '',
        'repair_failed_tool': '',
        'repair_failed_reason': '',
        'code_hash': '',
    }

    with open(saved_path, 'r', encoding='utf-8') as f:
        repaired_code = f.read()
    result['code_hash'] = hashlib.sha1(repaired_code.encode('utf-8')).hexdigest()

    if not action_valid:
        return result

    if not compile_ok(saved_path):
        return result

    result['compile_ok'] = 1
    repair_error = smart(saved_path, detect_time_limit, use_cache=False)
    repair_detail = get_last_smart_details()
    repair_counts = as_counts(repair_detail)
    result['repair_error'] = repair_error
    result['repair_total'] = sum(repair_counts.values()) if repair_error != -1 else -1
    result['repair_counts'] = repair_counts
    if repair_detail:
        result['repair_detect_status'] = repair_detail.get('status', '')
        result['repair_failed_tool'] = repair_detail.get('failed_tool', '')
        result['repair_failed_reason'] = repair_detail.get('failed_reason', '')
    if repair_error == -1:
        return result

    result['detect_ok'] = 1
    if target_vuln in VULN_KEYS:
        result['target_fixed'] = int(repair_counts.get(target_vuln, 0) == 0)
    if original_info['original_detect_ok']:
        result['total_not_worse'] = int(result['repair_total'] <= original_info['original_total'])
    result['weak_success'] = int(result['target_fixed'] and result['total_not_worse'])
    return result


def write_csv(path, rows, fieldnames):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def aggregate_summary(sample_rows, candidate_rows):
    per_type = defaultdict(lambda: {
        'test_set_count': 0,
        'evaluated_test_set_count': 0,
        'recommendation_count': 0,
        'action_valid_recommendation_count': 0,
        'compilable_patch_count': 0,
        'target_fixed_recommendation_count': 0,
        'weak_success_recommendation_count': 0,
        'weak_correct_patch_count': 0,
    })

    for sample in sample_rows:
        vuln_name = sample['target_vuln']
        row = per_type[vuln_name]
        row['test_set_count'] += 1
        row['evaluated_test_set_count'] += int(sample['original_detect_ok'])
        row['weak_correct_patch_count'] += int(sample['weak_correct_patch'])

    for candidate in candidate_rows:
        vuln_name = candidate['target_vuln']
        row = per_type[vuln_name]
        row['recommendation_count'] += 1
        row['action_valid_recommendation_count'] += int(candidate['action_valid'])
        row['compilable_patch_count'] += int(candidate['compile_ok'])
        row['target_fixed_recommendation_count'] += int(candidate['target_fixed'])
        row['weak_success_recommendation_count'] += int(candidate['weak_success'])

    ordered_vulns = [name for name in VULN_KEYS if name in per_type]
    extras = sorted(name for name in per_type.keys() if name not in ordered_vulns)
    summary_rows = []
    total_row = {
        'vuln_type': 'TOTAL',
        'test_set_count': 0,
        'evaluated_test_set_count': 0,
        'recommendation_count': 0,
        'action_valid_recommendation_count': 0,
        'compilable_patch_count': 0,
        'target_fixed_recommendation_count': 0,
        'weak_success_recommendation_count': 0,
        'weak_correct_patch_count': 0,
        'weak_correct_patch_pct': 0.0,
    }
    for vuln_name in ordered_vulns + extras:
        raw = per_type[vuln_name]
        row = {
            'vuln_type': vuln_name,
            'test_set_count': raw['test_set_count'],
            'evaluated_test_set_count': raw['evaluated_test_set_count'],
            'recommendation_count': raw['recommendation_count'],
            'action_valid_recommendation_count': raw['action_valid_recommendation_count'],
            'compilable_patch_count': raw['compilable_patch_count'],
            'target_fixed_recommendation_count': raw['target_fixed_recommendation_count'],
            'weak_success_recommendation_count': raw['weak_success_recommendation_count'],
            'weak_correct_patch_count': raw['weak_correct_patch_count'],
            'weak_correct_patch_pct': (
                raw['weak_correct_patch_count'] / raw['test_set_count'] if raw['test_set_count'] else 0.0
            ),
        }
        summary_rows.append(row)
        for key in (
            'test_set_count',
            'evaluated_test_set_count',
            'recommendation_count',
            'action_valid_recommendation_count',
            'compilable_patch_count',
            'target_fixed_recommendation_count',
            'weak_success_recommendation_count',
            'weak_correct_patch_count',
        ):
            total_row[key] += row[key]
    total_row['weak_correct_patch_pct'] = (
        total_row['weak_correct_patch_count'] / total_row['test_set_count'] if total_row['test_set_count'] else 0.0
    )
    summary_rows.append(total_row)
    return summary_rows


def print_summary(summary_rows):
    print('vuln_type,test_set,evaluated,recommendations,compilable,weak_correct,weak_correct_pct')
    for row in summary_rows:
        print(
            '{},{},{},{},{},{},{:.4f}'.format(
                row['vuln_type'],
                row['test_set_count'],
                row['evaluated_test_set_count'],
                row['recommendation_count'],
                row['compilable_patch_count'],
                row['weak_correct_patch_count'],
                row['weak_correct_patch_pct'],
            )
        )


def main():
    args = parse_args()
    os.environ['RLREP_DETECT_PROFILE'] = args.detect_profile
    context_config = build_context_config(
        args.context_mode,
        args.context_token_budget,
        args.context_max_nodes,
        args.context_max_hops,
        args.context_fallback,
        args.slither_image,
    )

    dataset_path = os.path.abspath(args.dataset_path)
    if os.path.basename(dataset_path.rstrip('/\\')) != 'newALLBUGS':
        raise ValueError(
            'evaluate_rlrep.py currently supports dataset_vul/newALLBUGS only because choose_action uses '
            'the built-in newALLBUGS repair directory'
        )
    model_dir = os.path.join(dataset_path, 'model')
    if args.model_path:
        model_path = os.path.abspath(args.model_path)
        model_epoch = None
    else:
        model_path, model_epoch = find_best_model_path(model_dir, args.model_name)
        if not model_path:
            raise FileNotFoundError(
                'No best-model checkpoint found in {} matching {}_<epoch>'.format(model_dir, args.model_name)
            )

    timestamp = time.strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.abspath(
        args.output_dir or os.path.join(dataset_path, 'eval', 'weak_eval_{}'.format(timestamp))
    )
    contracts_out_dir = os.path.join(output_dir, 'contracts')
    os.makedirs(contracts_out_dir, exist_ok=True)

    code_w2i, ast_w2i = load_vocab(dataset_path)
    contract_dir, code_dir, ast_dir = get_split_paths(dataset_path, args.split)
    selective_split = args.split
    if args.split in ('train', 'root', 'full'):
        selective_split = 'train'
    code_dir = prepare_context_directory(
        dataset_path,
        code_dir,
        contract_dir,
        selective_split,
        context_mode=args.context_mode,
        metadata_csv=args.metadata_csv,
        logger=None,
        context_config=context_config,
    )
    for required_path in (contract_dir, code_dir, ast_dir):
        if not os.path.isdir(required_path):
            raise FileNotFoundError('Required split path not found: {}'.format(required_path))
    sample_names = sorted(name for name in os.listdir(contract_dir) if name.endswith('.sol'))
    if args.max_samples > 0:
        sample_names = sample_names[:args.max_samples]

    config = Config_RL_multistep()
    model = Model(config)
    checkpoint = model.load(model_path)
    validate_checkpoint_context(
        checkpoint, context_config, purpose='evaluation',
        allow_legacy_evidence=args.allow_legacy_context_checkpoint)
    action_map = get_action()

    sample_rows = []
    candidate_rows = []
    target_source_counter = Counter()

    print('evaluate model={} split={} samples={} beam={} detect_profile={} context_mode={}'.format(
        model_path,
        args.split,
        len(sample_names),
        args.beam_size,
        args.detect_profile,
        args.context_mode,
    ))

    for index, filename in enumerate(sample_names, 1):
        sample_name = filename[:-4]
        contract_path = os.path.join(contract_dir, filename)
        code_path = os.path.join(code_dir, filename)
        ast_path = os.path.join(ast_dir, filename)
        in1, in2 = load_sample_inputs(code_path, ast_path, code_w2i, ast_w2i, config)
        all_preds, best_preds = model.beam_search_all(([in1], [in2]), args.beam_size)
        beam_preds = all_preds[:args.beam_size]
        if not beam_preds and best_preds:
            beam_preds = best_preds[:1]

        original_info = evaluate_original(contract_path, args.detect_time_limit)
        target_vuln, target_source, positive_types, fault_line = classify_target_vulnerability(
            contract_path,
            original_info['original_counts'],
            original_info['original_detect_ok'],
        )
        target_source_counter[target_source] += 1

        sample_candidate_dir = os.path.join(contracts_out_dir, sample_name)
        os.makedirs(sample_candidate_dir, exist_ok=True)

        seen_action_signatures = set()
        seen_code_hashes = set()
        sample_candidates = []
        for rank, pred in enumerate(beam_preds, 1):
            action_ids = [int(x) for x in pred]
            action_signature = ','.join(str(x) for x in action_ids)
            candidate = evaluate_candidate(
                sample_name,
                target_vuln,
                contract_path,
                sample_candidate_dir,
                rank,
                action_ids,
                action_map,
                original_info,
                args.detect_time_limit,
            )
            candidate['target_vuln'] = target_vuln
            candidate['target_source'] = target_source
            candidate['fault_line'] = fault_line
            candidate['original_detect_ok'] = int(original_info['original_detect_ok'])
            candidate['original_total'] = original_info['original_total']
            candidate['original_error'] = original_info['original_error']
            candidate['original_detect_status'] = original_info['original_detect_status']
            candidate['original_failed_tool'] = original_info['original_failed_tool']
            candidate['original_failed_reason'] = original_info['original_failed_reason']
            candidate['original_counts_json'] = counts_to_json(original_info['original_counts'])
            candidate['repair_counts_json'] = counts_to_json(candidate['repair_counts'])
            candidate['positive_detect_types'] = '|'.join(positive_types)
            candidate['duplicate_action'] = int(action_signature in seen_action_signatures)
            candidate['duplicate_code'] = int(candidate['code_hash'] in seen_code_hashes)
            seen_action_signatures.add(action_signature)
            seen_code_hashes.add(candidate['code_hash'])
            sample_candidates.append(candidate)
            candidate_rows.append(candidate)

        weak_correct_patch = any(candidate['weak_success'] for candidate in sample_candidates)
        sample_rows.append({
            'sample_name': sample_name,
            'target_vuln': target_vuln,
            'target_source': target_source,
            'positive_detect_types': '|'.join(positive_types),
            'fault_line': fault_line,
            'original_detect_ok': int(original_info['original_detect_ok']),
            'original_error': original_info['original_error'],
            'original_detect_status': original_info['original_detect_status'],
            'original_failed_tool': original_info['original_failed_tool'],
            'original_failed_reason': original_info['original_failed_reason'],
            'original_total': original_info['original_total'],
            'original_counts_json': counts_to_json(original_info['original_counts']),
            'recommendation_count': len(sample_candidates),
            'action_valid_recommendation_count': sum(candidate['action_valid'] for candidate in sample_candidates),
            'compilable_patch_count': sum(candidate['compile_ok'] for candidate in sample_candidates),
            'target_fixed_recommendation_count': sum(candidate['target_fixed'] for candidate in sample_candidates),
            'weak_success_recommendation_count': sum(candidate['weak_success'] for candidate in sample_candidates),
            'weak_correct_patch': int(weak_correct_patch),
        })

        print(
            '[{}/{}] {} target={} source={} original={} compile={} weak_success={} weak_correct={}'.format(
                index,
                len(sample_names),
                sample_name,
                target_vuln,
                target_source,
                original_info['original_total'],
                sum(candidate['compile_ok'] for candidate in sample_candidates),
                sum(candidate['weak_success'] for candidate in sample_candidates),
                int(weak_correct_patch),
            )
        )

    summary_rows = aggregate_summary(sample_rows, candidate_rows)
    target_source_rows = [
        {'target_source': source, 'count': target_source_counter[source]}
        for source in sorted(target_source_counter)
    ]

    sample_fields = [
        'sample_name',
        'target_vuln',
        'target_source',
        'positive_detect_types',
        'fault_line',
        'original_detect_ok',
        'original_error',
        'original_detect_status',
        'original_failed_tool',
        'original_failed_reason',
        'original_total',
        'original_counts_json',
        'recommendation_count',
        'action_valid_recommendation_count',
        'compilable_patch_count',
        'target_fixed_recommendation_count',
        'weak_success_recommendation_count',
        'weak_correct_patch',
    ]
    candidate_fields = [
        'sample_name',
        'rank',
        'target_vuln',
        'target_source',
        'positive_detect_types',
        'fault_line',
        'candidate_path',
        'action_ids',
        'action_names',
        'action_len',
        'duplicate_action',
        'duplicate_code',
        'action_valid',
        'compile_ok',
        'detect_ok',
        'original_detect_ok',
        'original_error',
        'original_detect_status',
        'original_failed_tool',
        'original_failed_reason',
        'original_total',
        'original_counts_json',
        'repair_error',
        'repair_total',
        'repair_counts_json',
        'target_fixed',
        'total_not_worse',
        'weak_success',
        'repair_detect_status',
        'repair_failed_tool',
        'repair_failed_reason',
        'code_hash',
    ]
    summary_fields = [
        'vuln_type',
        'test_set_count',
        'evaluated_test_set_count',
        'recommendation_count',
        'action_valid_recommendation_count',
        'compilable_patch_count',
        'target_fixed_recommendation_count',
        'weak_success_recommendation_count',
        'weak_correct_patch_count',
        'weak_correct_patch_pct',
    ]

    write_csv(os.path.join(output_dir, 'samples.csv'), sample_rows, sample_fields)
    write_csv(os.path.join(output_dir, 'candidates.csv'), candidate_rows, candidate_fields)
    write_csv(os.path.join(output_dir, 'summary.csv'), summary_rows, summary_fields)
    write_csv(os.path.join(output_dir, 'target_source_breakdown.csv'), target_source_rows, ['target_source', 'count'])

    with open(os.path.join(output_dir, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(
            {
                'dataset_path': dataset_path,
                'split': args.split,
                'model_path': model_path,
                'model_epoch': checkpoint.get('epoch', model_epoch),
                'best_positive_repair': checkpoint.get('best_positive_repair'),
                'beam_size': args.beam_size,
                'detect_profile': args.detect_profile,
                'detect_time_limit': args.detect_time_limit,
                'context_mode': args.context_mode,
                'context_config': context_config,
                'metadata_csv': args.metadata_csv,
                'sample_count': len(sample_rows),
                'summary': summary_rows,
                'target_source_breakdown': target_source_rows,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print_summary(summary_rows)
    print('output_dir={}'.format(output_dir))


if __name__ == '__main__':
    main()
