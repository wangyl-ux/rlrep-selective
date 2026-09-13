import hashlib
import json
import os
import re
import subprocess
import uuid
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed

from solidityparser_compat import tokenize_code_fragment

from preprocessing.context_config import (
    BACKEND,
    DEFAULT_SLITHER_IMAGE,
    GRAPH_SCHEMA_VERSION,
    RULE_VERSION,
    SOLC_VERSION,
    build_context_config,
    evidence_directory,
)
from preprocessing.selective_context import (
    build_context_record,
    build_original_context_fallback,
    choose_vulnerability_type,
    emit_log,
    find_fault_index,
    get_metadata_lookup,
)


_MARKER_RE = re.compile(r"//\s*(?:fault|fixed)\s+line", re.IGNORECASE)
_EXTERNAL_MARKERS = (".send(", ".transfer(", ".call(", ".call.value", ".delegatecall(", ".callcode(")
_ARITHMETIC_MARKERS = ("+", "-", "*", "/", "%", ".add(", ".sub(", ".mul(", ".div(")


class EvidenceFailure(Exception):
    pass


def marker_free_source(source):
    # Removing only marker text preserves newline count, so metadata and Slither
    # line numbers remain aligned. Slither analyzes exactly this cleaned source.
    return _MARKER_RE.sub("", source)


def source_hash(source):
    return hashlib.sha256(marker_free_source(source).encode("utf-8")).hexdigest()


def graph_cache_key(clean_source_hash, slither_image):
    value = "{}|{}|{}|image={}|schema={}|rules={}".format(
        clean_source_hash, BACKEND, SOLC_VERSION, slither_image,
        GRAPH_SCHEMA_VERSION, RULE_VERSION)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def atomic_write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + ".tmp." + uuid.uuid4().hex
    with open(temporary, "w", encoding="utf-8") as output_file:
        output_file.write(text)
        output_file.flush()
        os.fsync(output_file.fileno())
    os.replace(temporary, path)


def atomic_write_json(path, value):
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def _mount_path(path):
    return os.path.abspath(path)


def extract_graph_with_docker(source, source_digest, cache_dir, slither_image, timeout, force=False):
    cache_key = graph_cache_key(source_digest, slither_image)
    graph_dir = os.path.join(cache_dir, "graphs")
    cache_path = os.path.join(graph_dir, cache_key + ".json")
    if not force and os.path.isfile(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as cache_file:
                cached = json.load(cache_file)
            # Older runs may have cached a timeout or transient Docker failure.
            # Only successful graph facts are reusable; failures are retried.
            if cached.get("status") == "ok" and isinstance(cached.get("graph"), dict):
                cached["cache_hit"] = True
                return cached
        except (OSError, ValueError, TypeError):
            pass

    os.makedirs(graph_dir, exist_ok=True)
    task_id = uuid.uuid4().hex
    container_name = "rlrep-evidence-" + task_id
    task_root = os.path.join(cache_dir, "tmp", "task-" + task_id)
    input_dir = os.path.join(task_root, "input")
    output_dir = os.path.join(task_root, "output")
    os.makedirs(input_dir)
    os.makedirs(output_dir)
    input_path = os.path.join(input_dir, "input.sol")
    output_path = os.path.join(output_dir, "output.json")
    atomic_write_text(input_path, marker_free_source(source))
    extractor_path = os.path.join(os.path.dirname(__file__), "slither_graph_extract.py")
    command = [
        "docker", "run", "--rm", "--name", container_name,
        "--entrypoint", "python3",
        "-v", "{}:/data/input.sol:ro".format(_mount_path(input_path)),
        "-v", "{}:/data/output:rw".format(_mount_path(output_dir)),
        "-v", "{}:/opt/rlrep/slither_graph_extract.py:ro".format(_mount_path(extractor_path)),
        slither_image,
        "/opt/rlrep/slither_graph_extract.py", "/data/input.sol", "/data/output/output.json",
    ]
    result = {
        "cache_key": cache_key,
        "cache_hit": False,
        "source_hash": source_digest,
        "backend": BACKEND,
        "slither_image": slither_image,
        "solc_version": SOLC_VERSION,
        "status": "failed",
        "docker_exit_code": None,
        "docker_timeout": False,
        "docker_timeout_cleanup_exit_code": None,
        "stdout": "",
        "stderr": "",
        "graph": None,
    }
    try:
        completed = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=float(timeout), universal_newlines=True, check=False)
        result["docker_exit_code"] = completed.returncode
        result["stdout"] = (completed.stdout or "")[-4000:]
        result["stderr"] = (completed.stderr or "")[-4000:]
        if completed.returncode != 0:
            diagnostic = (result["stdout"] + "\n" + result["stderr"]).lower()
            if "pragma" in diagnostic and ("compiler" in diagnostic or "version" in diagnostic):
                result["failure_reason"] = "solc_0.4.25_incompatible"
            else:
                result["failure_reason"] = "slither_failed"
        elif not os.path.isfile(output_path):
            result["failure_reason"] = "graph_output_missing"
        else:
            try:
                with open(output_path, "r", encoding="utf-8") as graph_file:
                    graph = json.load(graph_file)
                if graph.get("schema_version") != GRAPH_SCHEMA_VERSION or not isinstance(graph.get("functions"), list):
                    raise ValueError("unsupported graph schema")
                result["graph"] = graph
                result["status"] = "ok"
            except (OSError, ValueError, TypeError) as exc:
                result["failure_reason"] = "graph_output_invalid:{}".format(exc)
    except subprocess.TimeoutExpired as exc:
        result["docker_timeout"] = True
        result["failure_reason"] = "docker_timeout"
        result["stdout"] = ((exc.stdout or b"").decode("utf-8", "replace")
                            if isinstance(exc.stdout, bytes) else (exc.stdout or ""))[-4000:]
        result["stderr"] = ((exc.stderr or b"").decode("utf-8", "replace")
                            if isinstance(exc.stderr, bytes) else (exc.stderr or ""))[-4000:]
        # The unique name guarantees that timeout cleanup can only target the
        # container created for this extraction, never another user's work.
        try:
            cleanup = subprocess.run(
                ["docker", "rm", "-f", container_name], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=15, universal_newlines=True, check=False)
            result["docker_timeout_cleanup_exit_code"] = cleanup.returncode
        except (OSError, subprocess.TimeoutExpired):
            pass
    except (OSError, ValueError) as exc:
        result["failure_reason"] = "docker_unavailable:{}".format(exc)
    finally:
        # Delete only this UUID-scoped task tree under the project-owned cache.
        for directory in (output_dir, input_dir):
            if os.path.isdir(directory):
                for name in os.listdir(directory):
                    path = os.path.join(directory, name)
                    if os.path.isfile(path):
                        os.remove(path)
                os.rmdir(directory)
        if os.path.isdir(task_root):
            os.rmdir(task_root)
    # A timeout, unavailable daemon, or transient compiler failure must not
    # become a permanent cache hit. Such failures remain visible in sample logs
    # and are attempted again on the next preprocessing run.
    if result.get("status") == "ok":
        atomic_write_json(cache_path, result)
    return result


def _mapping_lines(item):
    return item.get("source", {}).get("lines", []) or []


def _mapping_start(item):
    return int(item.get("source", {}).get("start", -1))


def _target_name(value):
    value = (value or "").strip()
    if value.lower() == "fallback":
        return "fallback"
    return value.split("(", 1)[0].strip()


def locate_target_function(graph, fault_line, target_function):
    requested = _target_name(target_function)
    candidates = []
    for function in graph.get("functions", []):
        if function.get("kind") != "function":
            continue
        name = _target_name(function.get("name"))
        name_matches = (not requested or name == requested or requested == "fallback" and not name)
        function_lines = _mapping_lines(function)
        node_covers = any(fault_line in _mapping_lines(node) for node in function.get("nodes", []))
        function_covers = fault_line in function_lines or node_covers
        if name_matches and function_covers:
            candidates.append(function)
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (
        0 if fault_line in _mapping_lines(item) else 1,
        len(_mapping_lines(item)) or 10 ** 9,
        _mapping_start(item), item.get("id", "")))[0]


def locate_fault_node(function, fault_line):
    candidates = [node for node in function.get("nodes", []) if fault_line in _mapping_lines(node)]
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (
        len(_mapping_lines(item)) or 10 ** 9,
        int(item.get("source", {}).get("length", 0)),
        _mapping_start(item), item.get("id", "")))[0]


def _variable_ids(node, field):
    return set(value.get("id", "") for value in node.get(field, []) if value.get("id"))


def _all_read_ids(node):
    return _variable_ids(node, "variables_read") | _variable_ids(node, "state_variables_read")


def _all_write_ids(node):
    return _variable_ids(node, "variables_written") | _variable_ids(node, "state_variables_written")


def _is_guard(node):
    expression = (node.get("expression") or "").lower()
    node_type = (node.get("type") or "").lower()
    return "require(" in expression or "assert(" in expression or "if" in node_type


def _is_external(node):
    if node.get("high_level_calls") or node.get("low_level_calls"):
        return True
    expression = (node.get("expression") or "").lower().replace(" ", "")
    return any(marker.replace(" ", "") in expression for marker in _EXTERNAL_MARKERS)


def _is_arithmetic(node):
    expression = (node.get("expression") or "").lower()
    return any(marker in expression for marker in _ARITHMETIC_MARKERS)


def _is_safemath(node):
    expression = (node.get("expression") or "").lower()
    return "safemath" in expression or any(marker in expression for marker in (".add(", ".sub(", ".mul(", ".div("))


def build_lightweight_graph(graph):
    nodes = {}
    node_function = {}
    local_lookup = {}
    functions = {function.get("id"): function for function in graph.get("functions", [])}
    for function in graph.get("functions", []):
        for node in function.get("nodes", []):
            node_id = node.get("id")
            if not node_id or node_id in nodes:
                continue
            nodes[node_id] = node
            node_function[node_id] = function.get("id")
            local_lookup[(function.get("id"), node.get("local_id"))] = node_id
    declaration_variables = {}
    for variable in graph.get("state_variables", []):
        if variable.get("id"):
            declaration_variables[variable["id"]] = variable
    # Compatibility safety net for Slither 0.6.1 builds where the contract-level
    # declaration collection is absent/incomplete: node state-variable facts still
    # carry the stable ID and declaration source mapping.
    for function in graph.get("functions", []):
        for node in function.get("nodes", []):
            for field in ("state_variables_read", "state_variables_written"):
                for variable in node.get(field, []):
                    if variable.get("id"):
                        declaration_variables.setdefault(variable["id"], variable)
    for variable in declaration_variables.values():
        node_id = "declaration:" + variable.get("id", "")
        if not variable.get("id") or node_id in nodes:
            continue
        nodes[node_id] = {
            "id": node_id,
            "local_id": node_id,
            "type": "STATE_VARIABLE_DECLARATION",
            "expression": "{} {}".format(variable.get("type", ""), variable.get("name", "")),
            "source": variable.get("source", {}),
            "variables_read": [],
            "variables_written": [],
            "state_variables_read": [],
            "state_variables_written": [],
            "declared_variable_id": variable.get("id"),
            "internal_calls": [],
            "high_level_calls": [],
            "low_level_calls": [],
        }
        node_function[node_id] = ""
    edges = set()
    for node_id, node in nodes.items():
        function_id = node_function[node_id]
        for local_id in node.get("sons_local", []):
            target = local_lookup.get((function_id, local_id))
            if target:
                edges.add((node_id, target, "CFG"))
        for local_id in node.get("fathers_local", []):
            source_id = local_lookup.get((function_id, local_id))
            if source_id:
                edges.add((source_id, node_id, "CFG"))

    by_function = defaultdict(list)
    for node_id in nodes:
        by_function[node_function[node_id]].append(node_id)
    for function_id, ids in by_function.items():
        ordered = sorted(ids, key=lambda item: (_mapping_start(nodes[item]), item))
        for index, writer_id in enumerate(ordered):
            written = _all_write_ids(nodes[writer_id])
            if not written:
                continue
            for reader_id in ordered[index + 1:]:
                if written & _all_read_ids(nodes[reader_id]):
                    # Slither 0.6.1 facts support a deterministic approximate
                    # LOCAL_RW link, not a precise SSA reaching-definition claim.
                    edges.add((writer_id, reader_id, "LOCAL_RW"))

    state_users = defaultdict(lambda: {"read": [], "write": []})
    for node_id, node in nodes.items():
        for variable_id in _variable_ids(node, "state_variables_read"):
            state_users[variable_id]["read"].append(node_id)
        for variable_id in _variable_ids(node, "state_variables_written"):
            state_users[variable_id]["write"].append(node_id)
    for users in state_users.values():
        for writer_id in users["write"]:
            for reader_id in users["read"]:
                if writer_id != reader_id:
                    edges.add((writer_id, reader_id, "STATE_RW"))
    for node_id, node in nodes.items():
        declared_id = node.get("declared_variable_id")
        if not declared_id:
            continue
        for user_id, user in nodes.items():
            if declared_id in (_all_read_ids(user) | _all_write_ids(user)):
                edges.add((node_id, user_id, "DECLARATION"))

    by_name = defaultdict(list)
    by_signature = defaultdict(list)
    for function in graph.get("functions", []):
        by_name[_target_name(function.get("name"))].append(function)
        by_signature[function.get("signature", "")].append(function)
    for node_id, node in nodes.items():
        caller_function = functions.get(node_function[node_id], {})
        calls = node.get("internal_calls", [])
        for call in calls:
            callees = by_signature.get(call.get("target_signature", ""), [])
            if not callees:
                callees = by_name.get(_target_name(call.get("target_name")), [])
            for callee in callees:
                callee_nodes = callee.get("nodes", [])
                if callee_nodes:
                    edges.add((node_id, callee_nodes[0]["id"], "CALL"))
        for modifier in caller_function.get("modifiers", []):
            targets = by_signature.get(modifier.get("signature", ""), [])
            if not targets:
                targets = by_name.get(_target_name(modifier.get("name")), [])
            for target in targets:
                if target.get("kind") == "modifier" and target.get("nodes"):
                    edges.add((node_id, target["nodes"][0]["id"], "MODIFIER"))

    for function_id, ids in by_function.items():
        guards = [node_id for node_id in ids if _is_guard(nodes[node_id])]
        for guard_id in guards:
            related = _all_read_ids(nodes[guard_id]) | _all_write_ids(nodes[guard_id])
            for operation_id in ids:
                if operation_id != guard_id and related & (_all_read_ids(nodes[operation_id]) | _all_write_ids(nodes[operation_id])):
                    # This is a shared-variable GUARD approximation, not a full
                    # control-dependence graph.
                    edges.add((guard_id, operation_id, "GUARD"))
    return nodes, node_function, functions, sorted(edges)


def shortest_hops(fault_id, edges, max_hops):
    adjacency = defaultdict(set)
    for left, right, unused_kind in edges:
        adjacency[left].add(right)
        adjacency[right].add(left)
    distances = {fault_id: 0}
    queue = deque([fault_id])
    while queue:
        current = queue.popleft()
        if distances[current] >= max_hops:
            continue
        for neighbor in sorted(adjacency[current]):
            if neighbor not in distances:
                distances[neighbor] = distances[current] + 1
                queue.append(neighbor)
    return distances


def add_candidate(candidates, node, priority, role):
    node_id = node.get("id")
    if not node_id:
        return
    entry = candidates.setdefault(node_id, {"node": node, "priority": priority, "roles": set()})
    entry["priority"] = min(entry["priority"], priority)
    entry["roles"].add(role)


def vulnerability_candidates(vuln_type, target_function, fault_node, nodes, node_function, functions, edges):
    if vuln_type == "TOD":
        # The current metadata contains no reliable ordered function pair or
        # detector dependency. Shared state alone is insufficient evidence of
        # TOD, so v1 intentionally performs no unconstrained cross-function walk.
        raise EvidenceFailure("tod_missing_reliable_cross_function_evidence")
    target_id = target_function.get("id")
    target_nodes = [node for node_id, node in nodes.items() if node_function[node_id] == target_id]
    fault_reads = _all_read_ids(fault_node)
    fault_writes = _all_write_ids(fault_node)
    fault_vars = fault_reads | fault_writes
    candidates = {}
    add_candidate(candidates, fault_node, 0, "fault_node")

    if vuln_type == "RE":
        call_reads = set()
        for node in target_nodes:
            if _is_external(node):
                call_reads.update(_all_read_ids(node))
        for node in target_nodes:
            if _is_external(node):
                add_candidate(candidates, node, 1, "re_external_call")
            if _variable_ids(node, "state_variables_written"):
                add_candidate(candidates, node, 1, "re_state_write")
            if _is_guard(node) and (_all_read_ids(node) & fault_vars):
                add_candidate(candidates, node, 2, "re_related_guard")
            if _all_write_ids(node) & (fault_reads | call_reads):
                add_candidate(candidates, node, 2, "re_call_argument_definition")
    elif vuln_type == "TX":
        role_vars = set()
        for node in target_nodes:
            if "tx.origin" in (node.get("expression") or "").lower():
                add_candidate(candidates, node, 1, "tx_origin_condition")
                role_vars.update(_all_read_ids(node))
        for node in target_nodes:
            if role_vars & (_all_read_ids(node) | _all_write_ids(node)):
                add_candidate(candidates, node, 1 if "tx.origin" in (node.get("expression") or "").lower() else 2,
                              "tx_role_variable")
            if _is_guard(node) and role_vars & _all_read_ids(node):
                add_candidate(candidates, node, 2, "tx_permission_guard")
        for node in nodes.values():
            if node.get("declared_variable_id") in role_vars:
                add_candidate(candidates, node, 2, "tx_role_declaration")
    elif vuln_type == "IO":
        for node in target_nodes:
            if _is_arithmetic(node):
                add_candidate(candidates, node, 1, "io_arithmetic")
            if node.get("id") != fault_node.get("id") and _all_write_ids(node) & fault_reads:
                add_candidate(candidates, node, 1, "io_operand_definition")
            if node.get("id") != fault_node.get("id") and _all_read_ids(node) & fault_writes:
                add_candidate(candidates, node, 2, "io_result_use")
            if _is_guard(node) and _all_read_ids(node) & fault_vars:
                add_candidate(candidates, node, 2, "io_operand_guard")
            if _is_safemath(node):
                add_candidate(candidates, node, 2, "io_safemath_call")
        for node in nodes.values():
            if node.get("declared_variable_id") in fault_vars:
                add_candidate(candidates, node, 1, "io_operand_type_declaration")
    elif vuln_type == "ED":
        call_results = _all_write_ids(fault_node)
        for node in target_nodes:
            if _is_external(node):
                add_candidate(candidates, node, 1, "ed_external_call")
                call_results.update(_all_write_ids(node))
        for node in target_nodes:
            if call_results & _all_write_ids(node):
                add_candidate(candidates, node, 1, "ed_call_result")
            if _is_guard(node) and call_results & _all_read_ids(node):
                add_candidate(candidates, node, 2, "ed_result_check")
            if _mapping_start(node) > _mapping_start(fault_node) and _variable_ids(node, "state_variables_written"):
                add_candidate(candidates, node, 2, "ed_post_call_state_update")
            if _all_write_ids(node) & fault_reads:
                add_candidate(candidates, node, 3, "ed_call_argument_source")

    # A single related modifier or internal callee summary is deliberately P3.
    related_edge_kinds = {"MODIFIER", "CALL"}
    for left, right, kind in edges:
        if kind in related_edge_kinds and (left in candidates or left == fault_node.get("id")) and right in nodes:
            add_candidate(candidates, nodes[right], 3 if vuln_type != "TX" else 2,
                          "related_{}".format(kind.lower()))
            callee_id = node_function.get(right)
            if vuln_type == "TX":
                for node_id, node in nodes.items():
                    if node_function.get(node_id) == callee_id and _is_guard(node):
                        add_candidate(candidates, node, 3, "tx_modifier_permission_guard")
    return candidates


def _slice_source(clean_source, node):
    mapping = node.get("source", {})
    start = int(mapping.get("start", -1))
    length = int(mapping.get("length", 0))
    if start < 0 or length <= 0:
        return ""
    raw = clean_source.encode("utf-8")
    return raw[start:start + length].decode("utf-8", "replace").strip()


def select_budgeted_context(source, graph, row, token_budget, max_nodes, max_hops,
                            diagnostics=None):
    nodes, node_function, functions, edges = build_lightweight_graph(graph)
    if diagnostics is not None:
        diagnostics["graph_node_count"] = len(nodes)
        diagnostics["graph_edge_count"] = len(edges)
    fault_line = int(row.get("fault_line") or 0)
    target = locate_target_function(graph, fault_line, row.get("target_function", ""))
    if target is None:
        raise EvidenceFailure("target_function_not_found")
    if diagnostics is not None:
        diagnostics["target_function_id"] = target.get("id")
    fault = locate_fault_node(target, fault_line)
    if fault is None:
        raise EvidenceFailure("fault_line_not_mapped_to_node")
    if diagnostics is not None:
        diagnostics["fault_node_id"] = fault.get("id")
        diagnostics["fault_node_matched"] = True
    vuln_type, unused_source = choose_vulnerability_type(row)
    if not vuln_type:
        raise EvidenceFailure("unusable_vulnerability_type")
    candidates = vulnerability_candidates(vuln_type, target, fault, nodes, node_function, functions, edges)
    if len(candidates) <= 1:
        raise EvidenceFailure("no_supporting_graph_evidence")
    distances = shortest_hops(fault["id"], edges, int(max_hops))

    clean_source = marker_free_source(source)
    prepared = {}
    for node_id, entry in candidates.items():
        fragment = _slice_source(clean_source, entry["node"])
        try:
            tokens = tokenize_code_fragment(fragment)
        except Exception as exc:
            raise EvidenceFailure("tokenization_failed:{}".format(exc))
        if fragment and tokens:
            prepared[node_id] = dict(entry, fragment=fragment, tokens=tokens)
    if fault["id"] not in prepared:
        raise EvidenceFailure("fault_node_source_unusable")

    selected = [prepared[fault["id"]]]
    selected_ids = {fault["id"]}
    covered_roles = set(selected[0]["roles"])
    token_count = len(selected[0]["tokens"])
    while len(selected) < int(max_nodes):
        available = []
        for node_id, entry in prepared.items():
            if node_id in selected_ids:
                continue
            hop = distances.get(node_id)
            if hop is None or hop > int(max_hops):
                continue
            start = _mapping_start(entry["node"])
            fault_start = _mapping_start(fault)
            available.append((
                entry["priority"], hop,
                0 if entry["roles"] - covered_roles else 1,
                len(entry["tokens"]), abs(start - fault_start), start, node_id, entry))
        if not available:
            break
        available.sort(key=lambda item: item[:-1])
        chosen = available[0][-1]
        additional = len(chosen["tokens"]) + 1  # the existing <sep> sequence token
        if token_count + additional > int(token_budget):
            prepared.pop(chosen["node"]["id"], None)
            continue
        selected.append(chosen)
        selected_ids.add(chosen["node"]["id"])
        covered_roles.update(chosen["roles"])
        token_count += additional
    if len(selected) <= 1:
        raise EvidenceFailure("no_supporting_evidence_within_budget")

    spans = []
    evidence_rows = []
    for entry in selected:
        mapping = entry["node"]["source"]
        spans.append((int(mapping["start"]), int(mapping["start"]) + int(mapping["length"]), entry))
        evidence_rows.append({
            "node_id": entry["node"]["id"],
            "lines": mapping.get("lines", []),
            "priority": entry["priority"],
            "tags": sorted(entry["roles"]),
            "hop": distances.get(entry["node"]["id"], 0),
        })
    spans.sort(key=lambda item: (item[0], item[1], item[2]["node"]["id"]))
    merged = []
    for start, end, entry in spans:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    raw = clean_source.encode("utf-8")
    parts = []
    final_token_count = 0
    for start, end in merged:
        fragment = raw[start:end].decode("utf-8", "replace").strip()
        try:
            tokens = tokenize_code_fragment(fragment)
        except Exception as exc:
            raise EvidenceFailure("tokenization_failed:{}".format(exc))
        if tokens:
            parts.append(" ".join(tokens))
            final_token_count += len(tokens)
    final_token_count += max(0, len(parts) - 1)
    return " <sep> ".join(parts), {
        "vulnerability_type": vuln_type,
        "target_function_id": target.get("id"),
        "fault_node_id": fault.get("id"),
        "fault_node_matched": True,
        "selected_source_lines": sorted(set(line for item in evidence_rows for line in item["lines"])),
        "evidence": sorted(evidence_rows, key=lambda item: (min(item["lines"] or [10 ** 9]), item["node_id"])),
        "selected_token_count": final_token_count,
        "graph_node_count": len(nodes),
        "graph_edge_count": len(edges),
    }


def selective_fallback(sample_name, contract_path, original_context_path, row, match_method, source,
                       fallback_mode="selective_v1"):
    if fallback_mode == "selective_v1":
        try:
            built = build_context_record(
                sample_name, contract_path, original_context_path, row, match_method, source.splitlines(True))
            if isinstance(built, tuple) and built[1]:
                return built[1], "selective_v1"
        except Exception:
            pass
    return build_original_context_fallback(original_context_path), "original"


def evidence_log_dir(dataset_path, split_name, context_config):
    return os.path.join(dataset_path, "evidence_context_logs", split_name, context_config["config_hash"][:12])


def prepare_evidence_context_directory(dataset_path, original_code_dir, contract_dir, split_name,
                                       metadata_csv="", workers=1, max_samples=0, force=False,
                                       slither_image=DEFAULT_SLITHER_IMAGE, docker_timeout=120,
                                       context_token_budget=64, context_max_nodes=8,
                                       context_max_hops=2, context_fallback="selective_v1",
                                       logger=None):
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    dataset_path = os.path.abspath(dataset_path)
    try:
        inside_project = os.path.commonpath([project_root, dataset_path]) == project_root
    except ValueError:
        inside_project = False
    if not inside_project:
        raise ValueError("evidence_graph cache/output must remain inside the current RLRep project: {}".format(dataset_path))
    config = build_context_config(
        "evidence_graph", context_token_budget, context_max_nodes, context_max_hops,
        context_fallback, slither_image)
    output_dir = evidence_directory(os.path.abspath(original_code_dir), config)
    log_dir = evidence_log_dir(dataset_path, split_name, config)
    cache_dir = os.path.join(dataset_path, "evidence_graph_cache")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    metadata_lookup = get_metadata_lookup(dataset_path, metadata_csv)
    all_names = sorted(name for name in os.listdir(original_code_dir) if name.endswith(".sol"))
    names = all_names[:int(max_samples)] if int(max_samples) > 0 else all_names
    records = []
    fallback_counts = Counter()
    type_stats = defaultdict(lambda: Counter(samples=0, success=0, fallback=0))
    extraction_by_hash = {}
    # Pre-group by marker-free source hash, then run at most one container per
    # unique source. This also prevents duplicate samples/fault markers from
    # racing to populate the same cache entry.
    unique_sources = {}
    for sample_name in names:
        contract_path = os.path.join(contract_dir, sample_name)
        original_path = os.path.join(original_code_dir, sample_name)
        row, unused_match = (metadata_lookup.match(sample_name, contract_path, original_path)
                             if metadata_lookup.loaded else (None, "metadata_missing"))
        vuln_type, unused_source = choose_vulnerability_type(row or {})
        if row is None or not vuln_type or vuln_type == "TOD" or not os.path.isfile(contract_path):
            continue
        with open(contract_path, "r", encoding="utf-8", errors="ignore") as contract_file:
            candidate_source = contract_file.read()
        if find_fault_index(candidate_source.splitlines(True), row)[0] < 0:
            continue
        digest = source_hash(candidate_source)
        unique_sources.setdefault(digest, candidate_source)
    with ThreadPoolExecutor(max_workers=int(workers)) as executor:
        future_hashes = {
            executor.submit(
                extract_graph_with_docker, candidate_source, digest, cache_dir,
                slither_image, docker_timeout, force): digest
            for digest, candidate_source in sorted(unique_sources.items())
        }
        for future in as_completed(future_hashes):
            digest = future_hashes[future]
            try:
                extraction_by_hash[digest] = future.result()
            except Exception as exc:
                extraction_by_hash[digest] = {
                    "status": "failed", "failure_reason": "docker_worker_failed:{}".format(exc),
                    "docker_exit_code": None, "docker_timeout": False, "cache_hit": False,
                }
    for sample_name in names:
        source = ""
        contract_path = os.path.join(contract_dir, sample_name)
        original_path = os.path.join(original_code_dir, sample_name)
        output_path = os.path.join(output_dir, sample_name)
        row, match_method = (metadata_lookup.match(sample_name, contract_path, original_path)
                             if metadata_lookup.loaded else (None, "metadata_missing"))
        record = {
            "sample_name": sample_name,
            "metadata_match_method": match_method,
            "vulnerability_type": "",
            "target_function": row.get("target_function", "") if row else "",
            "fault_line": row.get("fault_line", "") if row else "",
            "graph_extraction_status": "not_run",
            "source_hash": "",
            "graph_node_count": 0,
            "graph_edge_count": 0,
            "fault_node_matched": False,
            "selected_source_lines": [],
            "evidence": [],
            "selected_token_count": 0,
            "backend": BACKEND,
            "slither_image": slither_image,
            "docker_exit_code": None,
            "docker_timeout": False,
            "fallback": True,
            "fallback_to": "",
            "fallback_reason": "",
        }
        serialized = ""
        try:
            with open(contract_path, "r", encoding="utf-8", errors="ignore") as contract_file:
                source = contract_file.read()
            digest = source_hash(source)
            record["source_hash"] = digest
            if row is None:
                raise EvidenceFailure("metadata_missing_or_unmatched")
            vuln_type, unused_source = choose_vulnerability_type(row)
            record["vulnerability_type"] = vuln_type
            if not vuln_type:
                raise EvidenceFailure("unusable_vulnerability_type")
            if vuln_type == "TOD":
                raise EvidenceFailure("tod_missing_reliable_cross_function_evidence")
            fault_index, unused_fault_source = find_fault_index(source.splitlines(True), row)
            if fault_index < 0:
                raise EvidenceFailure("fault_line_missing")
            selection_row = dict(row)
            selection_row["fault_line"] = str(fault_index + 1)
            record["fault_line"] = fault_index + 1
            extraction = extraction_by_hash[digest]
            record.update({
                "graph_extraction_status": extraction.get("status", "failed"),
                "docker_exit_code": extraction.get("docker_exit_code"),
                "docker_timeout": extraction.get("docker_timeout", False),
                "graph_cache_hit": extraction.get("cache_hit", False),
                "graph_cache_key": extraction.get("cache_key", ""),
            })
            if extraction.get("status") != "ok":
                raise EvidenceFailure(extraction.get("failure_reason", "graph_extraction_failed"))
            serialized, details = select_budgeted_context(
                source, extraction["graph"], selection_row, context_token_budget,
                context_max_nodes, context_max_hops, diagnostics=record)
            record.update(details)
            record["fallback"] = False
        except (EvidenceFailure, OSError, ValueError, TypeError) as exc:
            record["fallback_reason"] = str(exc)
            serialized, record["fallback_to"] = selective_fallback(
                sample_name, contract_path, original_path, row, match_method,
                source, context_fallback)
            fallback_counts[record["fallback_reason"]] += 1
        if not serialized:
            serialized = build_original_context_fallback(original_path)
            record["fallback"] = True
            record["fallback_to"] = "original"
            record["fallback_reason"] = record["fallback_reason"] or "empty_context"
        atomic_write_text(output_path, serialized.rstrip() + "\n")
        records.append(record)
        vuln_key = record["vulnerability_type"] or "UNKNOWN"
        type_stats[vuln_key]["samples"] += 1
        type_stats[vuln_key]["fallback" if record["fallback"] else "success"] += 1
        emit_log(logger, "[evidence_graph] sample={} type={} target={} fault_line={} extraction={} "
                 "nodes={} edges={} tokens={} lines={} fallback={} reason={}".format(
                     sample_name, vuln_key, record["target_function"], record["fault_line"],
                     record["graph_extraction_status"], record["graph_node_count"],
                     record["graph_edge_count"], record["selected_token_count"],
                     record["selected_source_lines"], record["fallback"], record["fallback_reason"] or "none"))
    with open(os.path.join(log_dir, "samples.jsonl"), "w", encoding="utf-8") as log_file:
        for record in records:
            log_file.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    complete = len(names) == len(all_names)
    manifest = {
        "split": split_name,
        "context_config": config,
        "output_dir": output_dir,
        "metadata_csv": metadata_lookup.csv_path,
        "processed_samples": names,
        "expected_sample_count": len(all_names),
        "processed_sample_count": len(names),
        "complete": complete,
        "success_count": sum(1 for record in records if not record["fallback"]),
        "fallback_count": sum(1 for record in records if record["fallback"]),
        "fallback_reasons": dict(fallback_counts),
        "by_vulnerability_type": {key: dict(value) for key, value in sorted(type_stats.items())},
        "limitations": [
            "LOCAL_RW and GUARD edges are deterministic approximations, not precise SSA def-use/control dependence",
            "TOD falls back without reliable ordered function-pair metadata or detector dependency evidence",
            "Stage 2 ED/TOD semantic-gate coverage is unchanged by this preprocessing-only feature",
        ],
    }
    total = float(len(records))
    manifest["success_rate"] = manifest["success_count"] / total if total else 0.0
    manifest["fallback_rate"] = manifest["fallback_count"] / total if total else 0.0
    for stats in manifest["by_vulnerability_type"].values():
        type_total = float(stats["samples"])
        stats["success_rate"] = stats["success"] / type_total if type_total else 0.0
        stats["fallback_rate"] = stats["fallback"] / type_total if type_total else 0.0
    atomic_write_json(os.path.join(output_dir, "manifest.json"), manifest)
    atomic_write_json(os.path.join(log_dir, "summary.json"), manifest)
    emit_log(logger, "[evidence_graph] split={} processed={}/{} success={} fallback={} complete={} output={}".format(
        split_name, len(names), len(all_names), manifest["success_count"], manifest["fallback_count"], complete, output_dir))
    if complete and manifest["success_count"] == 0:
        raise RuntimeError(
            "evidence_graph preprocessing produced zero successful graph contexts for complete split {}. "
            "Inspect {} before training; the fallback-only manifest is intentionally rejected.".format(
                split_name, os.path.join(log_dir, "summary.json")))
    return output_dir


def require_prepared_evidence_directory(dataset_path, original_code_dir, contract_dir, split_name,
                                        context_config, metadata_csv="", logger=None):
    output_dir = evidence_directory(os.path.abspath(original_code_dir), context_config)
    manifest_path = os.path.join(output_dir, "manifest.json")
    command = ("python prepare_evidence_context.py --dataset-path {} --splits {} --workers 1 "
               "--context-token-budget {} --context-max-nodes {} --context-max-hops {} "
               "--context-fallback {} --slither-image {}").format(
                   dataset_path, split_name, context_config["token_budget"], context_config["max_nodes"],
                   context_config["max_hops"], context_config["fallback"], context_config["slither_image"])
    if metadata_csv:
        command += " --metadata-csv {}".format(metadata_csv)
    if not os.path.isfile(manifest_path):
        raise RuntimeError("evidence_graph context is not prepared for split {}. Run: {}".format(split_name, command))
    try:
        with open(manifest_path, "r", encoding="utf-8") as manifest_file:
            manifest = json.load(manifest_file)
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("invalid evidence_graph manifest {}: {}. Re-run: {}".format(manifest_path, exc, command))
    expected = sorted(name for name in os.listdir(original_code_dir) if name.endswith(".sol"))
    missing = [name for name in expected if not os.path.isfile(os.path.join(output_dir, name))]
    expected_metadata_csv = get_metadata_lookup(dataset_path, metadata_csv).csv_path
    manifest_metadata_csv = manifest.get("metadata_csv") or ""
    metadata_mismatch = os.path.abspath(manifest_metadata_csv) != os.path.abspath(expected_metadata_csv)
    if (manifest.get("context_config") != context_config or not manifest.get("complete")
            or int(manifest.get("success_count") or 0) <= 0 or missing or metadata_mismatch):
        raise RuntimeError(
            "evidence_graph output is incomplete or uses different parameters for split {} "
            "(missing={} manifest_complete={} success_count={} metadata_mismatch={}). Re-run: {}".format(
                split_name, len(missing), manifest.get("complete"),
                manifest.get("success_count"), metadata_mismatch, command))
    emit_log(logger, "[evidence_graph] split={} read-only prepared directory={}".format(split_name, output_dir))
    return output_dir
