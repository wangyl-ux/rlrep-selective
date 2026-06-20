import os
import re
import subprocess

import solcx


PRAGMA_VERSION_RE = re.compile(r'(\d+)\s*\.\s*(\d+)\s*\.\s*(\d+)')


def extract_pragma_version(contract_path):
    with open(contract_path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'pragma solidity' not in line:
                continue
            matched = PRAGMA_VERSION_RE.search(line)
            if matched is None:
                break
            return '.'.join(matched.groups())
    raise ValueError('Unable to extract pragma version from {}'.format(contract_path))


def _compile_with_solc_binary(contract_path, solc_binary):
    completed = subprocess.run(
        [solc_binary, '--bin', contract_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or 'solc binary compile failed')


def compile_contract_file(contract_path):
    declared_version = extract_pragma_version(contract_path)

    if declared_version != '0.4.10':
        solcx.compile_files(contract_path, solc_version=declared_version)
        return {
            'declared_version': declared_version,
            'compiler_mode': 'solcx',
            'actual_version': declared_version,
            'fallback_used': 0,
        }

    solc_0410_binary = os.environ.get('RLREP_SOLC_0410_BINARY', '').strip()
    if solc_0410_binary:
        _compile_with_solc_binary(contract_path, solc_0410_binary)
        return {
            'declared_version': declared_version,
            'compiler_mode': 'external_binary',
            'actual_version': declared_version,
            'fallback_used': 0,
        }

    allow_fallback = os.environ.get('RLREP_SOLC_0410_FALLBACK', '').strip().lower() in ('1', 'true', 'yes')
    if allow_fallback:
        solcx.compile_files(contract_path, solc_version='0.4.11')
        return {
            'declared_version': declared_version,
            'compiler_mode': 'solcx_fallback',
            'actual_version': '0.4.11',
            'fallback_used': 1,
        }

    raise RuntimeError(
        'solc 0.4.10 is required for {}. py-solc-x does not support <0.4.11. '
        'Set RLREP_SOLC_0410_BINARY to a solc 0.4.10 binary, or set RLREP_SOLC_0410_FALLBACK=1 '
        'to approximate with solc 0.4.11.'.format(contract_path)
    )
