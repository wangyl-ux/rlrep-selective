#!/usr/bin/env python3
"""Serialize Slither 0.6.1 facts without leaking Slither objects into JSON.

This file is mounted read-only and executed inside the fixed Python 3.6 image.
It deliberately avoids dataclasses, annotations, f-strings, and newer Slither helpers
such as can_reenter/can_send_eth.  In Slither 0.6.1 source_mapping is commonly a
plain dictionary; object-style mappings are accepted only as a compatibility bonus.
"""
from __future__ import print_function

import json
import os
import sys

from slither.slither import Slither


SCHEMA_VERSION = 2


def stable_text(value):
    try:
        return str(value)
    except Exception:
        return "<unprintable>"


def source_mapping(value):
    mapping = getattr(value, "source_mapping", None)
    if isinstance(mapping, dict):
        raw = mapping
    else:
        raw = {
            "start": getattr(mapping, "start", -1),
            "length": getattr(mapping, "length", 0),
            "filename": getattr(mapping, "filename", ""),
            "lines": getattr(mapping, "lines", []),
        }
    lines = raw.get("lines") or []
    return {
        "start": int(raw.get("start", -1) if raw.get("start") is not None else -1),
        "length": int(raw.get("length", 0) if raw.get("length") is not None else 0),
        "filename": stable_text(raw.get("filename", "")),
        "lines": sorted(set(int(line) for line in lines if str(line).isdigit())),
    }


def variable_record(variable):
    owner = getattr(variable, "contract", None)
    owner_name = getattr(owner, "name", "") if owner is not None else ""
    name = getattr(variable, "canonical_name", None) or getattr(variable, "name", None) or stable_text(variable)
    return {
        "id": "{}:{}:{}".format(owner_name, stable_text(name), stable_text(getattr(variable, "type", ""))),
        "name": stable_text(name),
        "type": stable_text(getattr(variable, "type", "")),
        "source": source_mapping(variable),
    }


def variable_list(values):
    records = {}
    for value in values or []:
        record = variable_record(value)
        records[record["id"]] = record
    return [records[key] for key in sorted(records)]


def call_record(call):
    if isinstance(call, (list, tuple)):
        parts = [stable_text(item) for item in call]
        ir = call[-1] if call else None
    else:
        parts = [stable_text(call)]
        ir = call
    # In Slither 0.6.1 internal_calls contains SlithIR operations. Their target
    # declaration is exposed through ir.function rather than directly on the IR.
    target = getattr(ir, "function", None) or ir
    return {
        "text": " -> ".join(parts),
        "target_name": stable_text(getattr(target, "name", "")),
        "target_signature": stable_text(getattr(target, "full_name", "") or getattr(target, "signature", "")),
    }


def call_list(values):
    records = {}
    for value in values or []:
        record = call_record(value)
        records[record["text"]] = record
    return [records[key] for key in sorted(records)]


def node_local_id(node):
    raw = getattr(node, "node_id", None)
    if raw is not None:
        return stable_text(raw)
    mapping = source_mapping(node)
    return "source_{}_{}".format(mapping["start"], mapping["length"])


def function_name(function):
    return stable_text(getattr(function, "name", ""))


def function_signature(function):
    return stable_text(getattr(function, "full_name", "") or getattr(function, "signature", "") or function_name(function))


def serialize_function(contract, function, kind):
    declaring_contract = getattr(function, "contract_declarer", None) or getattr(function, "contract", None) or contract
    contract_name = stable_text(getattr(declaring_contract, "name", ""))
    signature = function_signature(function)
    function_id = "{}:{}:{}".format(contract_name, kind, signature)
    nodes = []
    for node in getattr(function, "nodes", []) or []:
        local_id = node_local_id(node)
        node_id = function_id + ":node:" + local_id
        irs = [stable_text(ir) for ir in (getattr(node, "irs", []) or [])]
        irs_ssa = [stable_text(ir) for ir in (getattr(node, "irs_ssa", []) or [])]
        nodes.append({
            "id": node_id,
            "local_id": local_id,
            "type": stable_text(getattr(node, "type", "")),
            "expression": stable_text(getattr(node, "expression", "") or ""),
            "source": source_mapping(node),
            "variables_read": variable_list(getattr(node, "variables_read", [])),
            "variables_written": variable_list(getattr(node, "variables_written", [])),
            "state_variables_read": variable_list(getattr(node, "state_variables_read", [])),
            "state_variables_written": variable_list(getattr(node, "state_variables_written", [])),
            "internal_calls": call_list(getattr(node, "internal_calls", [])),
            "high_level_calls": call_list(getattr(node, "high_level_calls", [])),
            "low_level_calls": call_list(getattr(node, "low_level_calls", [])),
            "sons_local": sorted(set(node_local_id(item) for item in (getattr(node, "sons", []) or []))),
            "fathers_local": sorted(set(node_local_id(item) for item in (getattr(node, "fathers", []) or []))),
            "immediate_dominator_local": (
                node_local_id(getattr(node, "immediate_dominator"))
                if getattr(node, "immediate_dominator", None) is not None else ""),
            "dominator_locals": sorted(set(
                node_local_id(item) for item in (getattr(node, "dominators", []) or []))),
            # IR is an intentionally bounded textual summary, not a pickle or a claim
            # of precise SSA reaching definitions.
            "irs": irs[:32],
            "irs_ssa": irs_ssa[:32],
        })
    nodes.sort(key=lambda item: (item["source"]["start"], item["id"]))
    modifiers = []
    for modifier in getattr(function, "modifiers", []) or []:
        modifiers.append({
            "name": function_name(modifier),
            "signature": function_signature(modifier),
        })
    return {
        "id": function_id,
        "contract": contract_name,
        "kind": kind,
        "name": function_name(function),
        "signature": signature,
        "source": source_mapping(function),
        "modifiers": sorted(modifiers, key=lambda item: (item["signature"], item["name"])),
        "nodes": nodes,
    }


def main(input_path, output_path):
    analyzer = Slither(input_path)
    contracts = []
    seen_functions = set()
    functions = []
    state_variables = {}
    for contract in getattr(analyzer, "contracts", []) or []:
        contract_name = stable_text(getattr(contract, "name", ""))
        contracts.append({
            "name": contract_name,
            "kind": stable_text(getattr(contract, "contract_kind", "contract")),
            "source": source_mapping(contract),
        })
        # Old Slither 0.6.1 builds may expose declarations through
        # state_variables instead of state_variables_declared. Merge both;
        # state_variables can include inherited entries, so deduplicate by ID.
        contract_state_variables = []
        contract_state_variables.extend(
            getattr(contract, "state_variables_declared", []) or [])
        contract_state_variables.extend(
            getattr(contract, "state_variables", []) or [])
        for variable in contract_state_variables:
            record = variable_record(variable)
            record["contract"] = contract_name
            state_variables[record["id"]] = record
        for kind, values in (
                ("function", getattr(contract, "functions", []) or []),
                ("modifier", getattr(contract, "modifiers", []) or [])):
            for function in values:
                record = serialize_function(contract, function, kind)
                if record["id"] in seen_functions:
                    continue
                seen_functions.add(record["id"])
                functions.append(record)
    functions.sort(key=lambda item: (item["source"]["start"], item["id"]))
    state_variable_records = sorted(
        state_variables.values(),
        key=lambda item: (item["source"]["start"], item["id"]))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "backend": "slither_docker_0.6.1",
        "solc_version": "0.4.25",
        "input_basename": os.path.basename(input_path),
        "contracts": sorted(contracts, key=lambda item: (item["source"]["start"], item["name"])),
        "state_variables": state_variable_records,
        "functions": functions,
    }
    with open(output_path, "w") as output_file:
        json.dump(payload, output_file, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: slither_graph_extract.py INPUT.sol OUTPUT.json", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
