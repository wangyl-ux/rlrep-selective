import argparse
import copy
import os
import pathlib
import sys
import yaml
import time as sleeptime
from datetime import timedelta
from multiprocessing import Manager, Pool, Process
from src.docker_api.docker_api import analyse_files
from src.interface.cli import create_parser, getRemoteDataset, isRemoteDataset, DATASET_CHOICES, TOOLS_CHOICES
from src.output_parser.SarifHolder import SarifHolder
from time import time, localtime, strftime
import multiprocessing

cfg_dataset_path = os.path.abspath('config/dataset/dataset.yaml')
with open(cfg_dataset_path, 'r') as ymlfile:
    try:
        cfg_dataset = yaml.safe_load(ymlfile)
    except yaml.YAMLError as exc:
        print(exc)

output_folder = strftime("%Y%m%d_%H%M", localtime())
os.makedirs('results/logs/', exist_ok=True)
pathlib.Path('results/logs/').mkdir(parents=True, exist_ok=True)
logs = open('results/logs/SmartBugs_' + output_folder + '.log', 'w')

VULN_KEYS = ('IO', 'TOD', 'TX', 'ED', 'RE')
DETECT_PROFILES = {
    'paper_default': {
        'tools': ['mythril', 'oyente', 'securify', 'slither'],
        'tool_vulns': {
            'mythril': ('RE', 'ED'),
            'oyente': ('IO',),
            'securify': ('TOD',),
            'slither': ('TX',),
        },
    },
    'slither_fast': {
        'tools': ['oyente', 'securify', 'slither'],
        'tool_vulns': {
            'oyente': ('IO',),
            'securify': ('TOD',),
            'slither': ('TX', 'ED', 'RE'),
        },
    },
    'sailfish_tod': {
        'tools': ['oyente', 'sailfish', 'slither'],
        'tool_vulns': {
            'oyente': ('IO',),
            'sailfish': ('TOD',),
            'slither': ('TX', 'ED', 'RE'),
        },
    },
}
SMART_RESULT_CACHE = {}
LAST_SMART_DETAILS = None


def _progress_log_enabled():
    return os.environ.get('RLREP_SMARTBUGS_PROGRESS', '0') == '1'


def _new_counts():
    return {key: 0 for key in VULN_KEYS}


def get_detect_profile_name():
    profile_name = os.environ.get('RLREP_DETECT_PROFILE', 'paper_default')
    if profile_name not in DETECT_PROFILES:
        print('[detect] unknown profile={}, fallback=paper_default'.format(profile_name))
        return 'paper_default'
    return profile_name


def _contract_label(contract_path):
    return os.path.basename(contract_path)


def _format_counts(counts, vuln_names):
    items = []
    for vuln_name in vuln_names:
        value = counts.get(vuln_name, 0)
        if value > 0:
            items.append('{}:{}'.format(vuln_name, value))
    if not items:
        return 'none'
    return ','.join(items)


def _log_tool_result(profile_name, contract_path, tool, status, vuln_names=None, counts=None, reason=None):
    message = '[detect] profile={} contract={} tool={} status={}'.format(
        profile_name,
        _contract_label(contract_path),
        tool,
        status,
    )
    if reason:
        message += ' reason={}'.format(reason)
    if counts is not None and vuln_names is not None:
        message += ' vulns={}'.format(_format_counts(counts, vuln_names))
    print(message)


def _log_cache_hit(profile_name, contract_path, counts):
    print(
        '[detect] profile={} contract={} status=cache_hit total={}'.format(
            profile_name,
            _contract_label(contract_path),
            _format_counts(counts, VULN_KEYS),
        )
    )


def _execution_failure_reason(execution_result):
    if execution_result is None:
        return 'no_result'
    if execution_result == {}:
        return 'empty_result'
    if execution_result.get('__timeout__'):
        return 'timeout'
    if execution_result.get('__exec_error__'):
        return execution_result['__exec_error__']
    return None


def _set_last_smart_details(detail):
    global LAST_SMART_DETAILS
    LAST_SMART_DETAILS = detail


def get_last_smart_details():
    if LAST_SMART_DETAILS is None:
        return None
    return copy.deepcopy(LAST_SMART_DETAILS)


def _parse_oyente(execution_result):
    counts = _new_counts()
    failure_reason = _execution_failure_reason(execution_result)
    if failure_reason is not None:
        return False, counts, failure_reason
    if 'analysis' not in execution_result.keys() or execution_result['analysis'] is None or execution_result['analysis'] == []:
        return False, counts, 'no_analysis'
    for obj in execution_result['analysis']:
        for obj2 in obj.get('errors', []):
            if obj2.get('message') == 'Integer Overflow.':
                counts['IO'] += 1
    return True, counts, None


def _parse_slither(execution_result):
    counts = _new_counts()
    failure_reason = _execution_failure_reason(execution_result)
    if failure_reason is not None:
        return False, counts, failure_reason
    if 'analysis' not in execution_result.keys() or execution_result['analysis'] is None or execution_result['analysis'] == []:
        return False, counts, 'no_analysis'
    for obj in execution_result['analysis']:
        check_name = obj.get('check', '')
        if check_name == 'tx-origin':
            counts['TX'] += 1
        elif check_name in ('unchecked-lowlevel', 'unchecked-send'):
            counts['ED'] += 1
        elif 'reentrancy' in check_name:
            counts['RE'] += 1
    return True, counts, None


def _parse_securify(execution_result):
    counts = _new_counts()
    failure_reason = _execution_failure_reason(execution_result)
    if failure_reason is not None:
        return False, counts, failure_reason
    if 'analysis' not in execution_result.keys() or execution_result['analysis'] is None or execution_result['analysis'] == {}:
        return False, counts, 'no_analysis'
    for cont in execution_result['analysis']:
        for ts in execution_result['analysis'][cont]['results']:
            if ts in ('TODReceiver', 'TODTransfer', 'TODAmount'):
                counts['TOD'] += len(execution_result['analysis'][cont]['results'][ts]['violations'])
                counts['TOD'] += len(execution_result['analysis'][cont]['results'][ts]['conflicts'])
    return True, counts, None


def _parse_mythril(execution_result):
    counts = _new_counts()
    failure_reason = _execution_failure_reason(execution_result)
    if failure_reason is not None:
        return False, counts, failure_reason
    if 'analysis' not in execution_result.keys() or execution_result['analysis'] == {}:
        return False, counts, 'no_analysis'
    if execution_result['analysis'].get('success') is False:
        return False, counts, 'analysis_failed'
    for obj in execution_result['analysis'].get('issues', []):
        title = obj.get('title', '')
        if title in ('Message call to external contract', 'State access after external call', 'DAO'):
            counts['RE'] += 1
        elif title == 'Unchecked CALL return value':
            counts['ED'] += 1
    return True, counts, None


def _parse_sailfish(execution_result):
    counts = _new_counts()
    failure_reason = _execution_failure_reason(execution_result)
    if failure_reason is not None:
        return False, counts, failure_reason
    if 'analysis' not in execution_result.keys() or execution_result['analysis'] is None:
        return False, counts, 'no_analysis'

    analysis = execution_result['analysis']
    if not isinstance(analysis, dict):
        raise TypeError('sailfish analysis must be a dict, got {}'.format(type(analysis).__name__))
    if 'dependency_info' not in analysis:
        raise KeyError('sailfish analysis missing dependency_info')

    dependency_info = analysis['dependency_info']
    if not isinstance(dependency_info, dict):
        raise TypeError('sailfish dependency_info must be a dict, got {}'.format(type(dependency_info).__name__))

    tod_count = 0
    for _, entries in dependency_info.items():
        if not isinstance(entries, list):
            raise TypeError('sailfish dependency_info entries must be a list')
        for entry in entries:
            if not isinstance(entry, dict):
                raise TypeError('sailfish dependency entry must be a dict')
            if entry.get('attack_type') == 'TOD':
                tod_count += 1

    counts['TOD'] = tod_count
    count_source = analysis.get('count_source', 'dependency_info')
    extra_parts = []
    if 'contractlint_pair_count' in analysis:
        extra_parts.append('contractlint_pairs={}'.format(analysis['contractlint_pair_count']))
    if 'symex_path_count' in analysis:
        extra_parts.append('symex_paths={}'.format(analysis['symex_path_count']))
    extra_suffix = ''
    if extra_parts:
        extra_suffix = ' ' + ' '.join(extra_parts)
    print('[detect] tool=sailfish count_source={} tod_count={}{}'.format(
        count_source,
        tod_count,
        extra_suffix,
    ))
    return True, counts, None


TOOL_PARSERS = {
    'oyente': _parse_oyente,
    'slither': _parse_slither,
    'securify': _parse_securify,
    'mythril': _parse_mythril,
    'sailfish': _parse_sailfish,
}


def _make_cache_key(contract_path, ltime, profile_name):
    abs_path = os.path.abspath(contract_path)
    try:
        mtime = os.path.getmtime(abs_path)
    except OSError:
        mtime = None
    return profile_name, ltime, abs_path, mtime

def analyse(args):
    global logs, output_folder
    (tool, file, sarif_outputs, import_path, output_version, nb_task, nb_task_done, total_execution, start_time, pipi0) = args
    try:
        start = time()
        nb_task_done.value += 1
        analyze_result = analyse_files(tool, file, logs, output_folder, sarif_outputs, output_version, import_path)
        total_execution.value += time() - start
        if _progress_log_enabled():
            duration = str(timedelta(seconds=round(time() - start)))
            task_sec = nb_task_done.value / (time() - start_time)
            remaining_time = str(timedelta(seconds=round((nb_task - nb_task_done.value) / task_sec)))
            sys.stdout.write('\x1b[1;37m' + 'Done [%d/%d, %s]: ' % (nb_task_done.value, nb_task, remaining_time) + '\x1b[0m')
            sys.stdout.write('\x1b[1;34m' + file + '\x1b[0m')
            sys.stdout.write('\x1b[1;37m' + ' [' + tool + '] in ' + duration + ' ' + '\x1b[0m' + '\n')
    except Exception as e:
        print(e)
        raise e
    pipi0.send(analyze_result)
    return analyze_result

def exec_cmd(args: argparse.Namespace, ltime):
    global logs, output_folder
    files_to_analyze = []
    for file in args.file:
        if os.path.basename(file).endswith('.sol'):
            files_to_analyze.append(file)
        elif os.path.isdir(file):
            if args.import_path == "FILE":
                args.import_path = file
            for root, dirs, files in os.walk(file):
                for name in files:
                    if name.endswith('.sol'):
                        files_to_analyze.append(os.path.join(root, name))
        else:
            print('%s is not a directory or a solidity file' % file)

    start_time = time()
    manager = Manager()
    nb_task_done = manager.Value('i', 0)
    total_execution = manager.Value('f', 0)
    nb_task = len(files_to_analyze) * len(args.tool)
    sarif_outputs = manager.dict()
    tasks = []
    file_names = []
    pipi = multiprocessing.Pipe()
    for file in files_to_analyze:
        for tool in args.tool:
            results_folder = 'results/' + tool + '/' + output_folder
            if not os.path.exists(results_folder):
                os.makedirs(results_folder)
            tasks.append((tool, file, sarif_outputs, args.import_path, args.output_version, nb_task, nb_task_done, total_execution, start_time, pipi[0]))
        file_names.append(os.path.splitext(os.path.basename(file))[0])
    for file_name in file_names:
        sarif_outputs[file_name] = SarifHolder()

    p = Process(target=analyse, args=(tasks[0],))
    p.start()
    p.join(ltime)
    if p.is_alive():
        p.terminate()
        p.join()
        sleeptime.sleep(0.1)
        return {'__timeout__': True}
    if not pipi[1].poll(0.1):
        return {'__exec_error__': 'no_response'}
    contract_inspection_reuslts = pipi[1].recv()
    return contract_inspection_reuslts

def smart(contract_path, ltime, use_cache=False):
    profile_name = get_detect_profile_name()
    profile = DETECT_PROFILES[profile_name]
    cache_key = _make_cache_key(contract_path, ltime, profile_name)
    if use_cache and cache_key in SMART_RESULT_CACHE:
        cached = SMART_RESULT_CACHE[cache_key]
        cache_detail = copy.deepcopy(cached['detail'])
        cache_detail['status'] = 'cache_hit'
        _set_last_smart_details(cache_detail)
        _log_cache_hit(profile_name, contract_path, cached['counts'])
        return cached['error']

    total_counts = _new_counts()
    for tool in profile['tools']:
        sys.argv[1:] = ['--tool', tool, '--file', contract_path]
        args = create_parser()
        execution_result = exec_cmd(args, ltime)
        ok, parsed_counts, reason = TOOL_PARSERS[tool](execution_result)
        _log_tool_result(
            profile_name,
            contract_path,
            tool,
            'ok' if ok else 'fail',
            profile['tool_vulns'][tool],
            parsed_counts,
            reason,
        )
        if not ok:
            _set_last_smart_details({
                'profile': profile_name,
                'contract': _contract_label(contract_path),
                'status': 'failed',
                'error': -1,
                'counts': total_counts.copy(),
                'failed_tool': tool,
                'failed_reason': reason or 'unknown',
            })
            return -1
        for vuln_name in profile['tool_vulns'][tool]:
            total_counts[vuln_name] += parsed_counts.get(vuln_name, 0)

    total_error = sum(total_counts.values())
    success_detail = {
        'profile': profile_name,
        'contract': _contract_label(contract_path),
        'status': 'done',
        'error': total_error,
        'counts': total_counts.copy(),
        'failed_tool': '',
        'failed_reason': '',
    }
    _set_last_smart_details(success_detail)
    print(
        '[detect] profile={} contract={} status=done total={}'.format(
            profile_name,
            _contract_label(contract_path),
            _format_counts(total_counts, VULN_KEYS),
        )
    )
    if use_cache:
        SMART_RESULT_CACHE[cache_key] = {
            'error': total_error,
            'counts': total_counts.copy(),
            'detail': copy.deepcopy(success_detail),
        }
    return total_error
