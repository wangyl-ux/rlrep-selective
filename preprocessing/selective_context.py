import csv
import json
import os
import re
from collections import Counter

from solidityparser_compat import tokenize_code_fragment


VALID_VULN_TYPES = {"ED", "IO", "RE", "TOD", "TX"}
DEFAULT_MAX_EXTRA_LINES = 6
FAULT_MARKER = "// fault line"
FIXED_MARKER = "// fixed line"

_METADATA_CACHE = {}

_EXTERNAL_CALL_MARKERS = (".send(", ".transfer(", ".call.value", ".call(", ".delegatecall(", ".callcode(")
_STATE_KEYWORDS = (
    "balance",
    "balances",
    "amount",
    "value",
    "total",
    "fund",
    "credit",
    "debit",
    "fee",
    "reward",
    "paid",
    "withdraw",
    "allowance",
    "allowed",
)
_AUTH_KEYWORDS = ("owner", "admin", "auth", "authorized", "privileged", "sender")
_TOD_KEYWORDS = (
    "approve",
    "allowance",
    "allowed",
    "spender",
    "_spender",
    "approval",
    "transferfrom",
    "delegateallowance",
)
_SAFE_MATH_MARKERS = (".add(", ".sub(", ".mul(", ".div(", "safemath")
_ARITHMETIC_MARKERS = ("+=", "-=", "*=", "/=", "++", "--", " + ", " - ", " * ", " / ")
_SOLIDITY_KEYWORDS = {
    "if",
    "else",
    "for",
    "while",
    "return",
    "require",
    "assert",
    "revert",
    "throw",
    "function",
    "modifier",
    "contract",
    "mapping",
    "address",
    "uint",
    "uint256",
    "uint128",
    "uint64",
    "int",
    "bool",
    "true",
    "false",
    "msg",
    "tx",
    "now",
    "this",
    "memory",
    "storage",
    "public",
    "private",
    "internal",
    "external",
    "view",
    "pure",
    "payable",
    "constant",
}


def emit_log(logger, message):
    if logger is not None:
        logger.info(message)
    else:
        print(message)


def normalize_relpath(value):
    if not value:
        return ""
    normalized = os.path.normpath(str(value).strip()).replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def basename_key(value):
    normalized = normalize_relpath(value)
    if not normalized:
        return ""
    return os.path.basename(normalized).lower()


def resolve_metadata_csv_path(dataset_path, metadata_csv=""):
    candidates = []
    if metadata_csv:
        if os.path.isabs(metadata_csv):
            candidates.append(metadata_csv)
        else:
            candidates.append(os.path.abspath(metadata_csv))
            candidates.append(os.path.abspath(os.path.join(dataset_path, metadata_csv)))
    candidates.extend(
        [
            os.path.join(dataset_path, "metadata", "metadata_fulldataset.csv"),
            os.path.join(dataset_path, "metadata", "metadata_fulldateset.csv"),
            os.path.join(dataset_path, "validation", "metadata", "metadata_fulldataset.csv"),
            os.path.join(dataset_path, "validation", "metadata", "metadata_fulldateset.csv"),
        ]
    )

    seen = set()
    for candidate in candidates:
        resolved = os.path.abspath(candidate)
        if resolved in seen:
            continue
        seen.add(resolved)
        if os.path.isfile(resolved):
            return resolved
    return ""


class MetadataLookup:
    def __init__(self, csv_path, dataset_path):
        self.csv_path = csv_path
        self.dataset_path = os.path.abspath(dataset_path)
        self.rows = []
        self.by_sample_id = {}
        self.by_contract_file = {}
        self.by_context_file = {}
        self.by_basename = {}
        self.loaded = False

        if not csv_path or not os.path.isfile(csv_path):
            return

        with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                normalized = {key: (value or "").strip() for key, value in row.items()}
                row_id = normalized.get("sample_id") or normalized.get("contract_file") or normalized.get("context_file")
                normalized["_row_id"] = row_id
                self.rows.append(normalized)
                self._index_row(normalized)
        self.loaded = True

    def _index_row(self, row):
        for field_name, target in (
            ("sample_id", self.by_sample_id),
            ("contract_file", self.by_contract_file),
            ("context_file", self.by_context_file),
        ):
            raw = row.get(field_name, "")
            normalized = normalize_relpath(raw)
            if normalized and normalized not in target:
                target[normalized] = row
            base = basename_key(raw)
            if base and base not in self.by_basename:
                self.by_basename[base] = row

    def _candidate_keys(self, path_value):
        if not path_value:
            return []
        abs_path = os.path.abspath(path_value)
        candidates = [
            normalize_relpath(os.path.relpath(abs_path, os.getcwd())),
            normalize_relpath(os.path.relpath(abs_path, self.dataset_path)),
            normalize_relpath(abs_path),
            basename_key(abs_path),
        ]
        result = []
        seen = set()
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            result.append(candidate)
        return result

    def match(self, sample_name, contract_path, context_path):
        contract_keys = self._candidate_keys(contract_path)
        context_keys = self._candidate_keys(context_path)
        sample_keys = [sample_name.lower(), sample_name]

        for key in contract_keys:
            row = self.by_sample_id.get(key)
            if row is not None:
                return row, "sample_id:contract_path"
        for key in context_keys:
            row = self.by_sample_id.get(key)
            if row is not None:
                return row, "sample_id:context_path"
        for key in contract_keys:
            row = self.by_contract_file.get(key)
            if row is not None:
                return row, "contract_file"
        for key in context_keys:
            row = self.by_context_file.get(key)
            if row is not None:
                return row, "context_file"
        for key in sample_keys:
            row = self.by_basename.get(key.lower())
            if row is not None:
                return row, "basename"
        return None, "unmatched"


def get_metadata_lookup(dataset_path, metadata_csv=""):
    resolved = resolve_metadata_csv_path(dataset_path, metadata_csv)
    cache_key = (os.path.abspath(dataset_path), resolved)
    if cache_key not in _METADATA_CACHE:
        _METADATA_CACHE[cache_key] = MetadataLookup(resolved, dataset_path)
    return _METADATA_CACHE[cache_key]


def strip_marker(line):
    return line.replace(FAULT_MARKER, "").replace(FIXED_MARKER, "").rstrip()


def clean_line(line):
    return strip_marker(line).strip()


def is_meaningful_line(line):
    stripped = clean_line(line)
    if not stripped:
        return False
    if stripped in ("{", "}", ");"):
        return False
    return True


def lower_line(line):
    return clean_line(line).lower()


def line_has_any(line, keywords):
    lowered = lower_line(line)
    return any(keyword in lowered for keyword in keywords)


def is_guard_line(line):
    lowered = lower_line(line)
    return "require(" in lowered or "assert(" in lowered or lowered.startswith("if ") or " if(" in lowered or lowered.startswith("if(")


def is_external_call_line(line):
    lowered = lower_line(line)
    return any(marker in lowered for marker in _EXTERNAL_CALL_MARKERS)


def is_state_update_line(line):
    lowered = lower_line(line)
    return any(marker in lowered for marker in ("+=", "-=", "++", "--", "="))


def is_arithmetic_line(line):
    lowered = lower_line(line)
    if any(marker in lowered for marker in _ARITHMETIC_MARKERS):
        return True
    return any(marker in lowered for marker in _SAFE_MATH_MARKERS)


def parse_bool(value):
    return str(value).strip().lower() in ("1", "true", "yes")


def choose_vulnerability_type(row):
    strict_type = row.get("strict_type", "").strip().upper()
    if strict_type in VALID_VULN_TYPES:
        return strict_type, "strict_type"

    paper_family = row.get("paper_family", "").strip().upper()
    if paper_family in VALID_VULN_TYPES:
        return paper_family, "paper_family"

    return "", ""


def find_fault_index(lines, row):
    metadata_fault_line = row.get("fault_line", "").strip()
    metadata_index = None
    if metadata_fault_line.isdigit():
        candidate = int(metadata_fault_line) - 1
        if 0 <= candidate < len(lines):
            metadata_index = candidate

    marker_index = None
    for index, line in enumerate(lines):
        if FAULT_MARKER in line:
            marker_index = index
            break

    if metadata_index is not None and FAULT_MARKER in lines[metadata_index]:
        return metadata_index, "metadata_exact"
    if marker_index is not None:
        if metadata_index is not None and metadata_index != marker_index:
            return marker_index, "marker_override"
        return marker_index, "marker"
    if metadata_index is not None:
        return metadata_index, "metadata"
    return -1, "missing"


def get_original_context_indices(lines, fault_index):
    if fault_index < 0:
        return []
    result = []
    for index in (fault_index - 1, fault_index, fault_index + 1):
        if 0 <= index < len(lines) and is_meaningful_line(lines[index]):
            result.append(index)
    return result


def find_signature_index(lines, fault_index, target_function):
    target_function = (target_function or "").strip()
    fallback_regex = re.compile(r"^\s*function\s*\(")
    direct_regex = None
    modifier_regex = None
    if target_function and target_function.lower() != "fallback":
        direct_regex = re.compile(r"\bfunction\s+{}\b".format(re.escape(target_function)))
        modifier_regex = re.compile(r"\bmodifier\s+{}\b".format(re.escape(target_function)))

    start = max(0, fault_index - 200)
    for index in range(fault_index, start - 1, -1):
        line = lines[index]
        if direct_regex is not None and direct_regex.search(line):
            return index
        if modifier_regex is not None and modifier_regex.search(line):
            return index
        if target_function.lower() == "fallback" and fallback_regex.search(line):
            return index
        if "function " in line or re.match(r"^\s*function\s*\(", line) or "modifier " in line or "constructor" in line:
            return index
    return -1


def find_block_end(lines, start_index):
    if start_index < 0:
        return -1
    balance = 0
    seen_open = False
    for index in range(start_index, len(lines)):
        line = lines[index]
        open_count = line.count("{")
        close_count = line.count("}")
        if open_count > 0:
            seen_open = True
        balance += open_count
        balance -= close_count
        if seen_open and balance <= 0:
            return index
    return min(len(lines) - 1, start_index + 80)


def find_function_bounds(lines, fault_index, target_function):
    signature_index = find_signature_index(lines, fault_index, target_function)
    if signature_index < 0:
        return None
    end_index = find_block_end(lines, signature_index)
    if end_index < signature_index:
        return None
    return signature_index, end_index


class CandidateCollector:
    def __init__(self, lines, fault_index, bounds):
        self.lines = lines
        self.fault_index = fault_index
        self.bounds = bounds
        self.entries = {}
        self.add(fault_index, 0, "fault_line")

    def contains(self, index):
        return index in self.entries

    def is_in_bounds(self, index):
        if index < 0 or index >= len(self.lines):
            return False
        if not is_meaningful_line(self.lines[index]):
            return False
        if self.bounds is None:
            return True
        return self.bounds[0] <= index <= self.bounds[1]

    def add(self, index, priority, tag):
        if not self.is_in_bounds(index):
            return
        entry = self.entries.get(index)
        if entry is None:
            self.entries[index] = {"priority": priority, "tags": [tag]}
            return
        entry["priority"] = min(entry["priority"], priority)
        if tag not in entry["tags"]:
            entry["tags"].append(tag)

    def add_nearest(self, indices, priority, tag, limit):
        ranked = sorted(indices, key=lambda item: (abs(item - self.fault_index), item))
        for index in ranked[:limit]:
            self.add(index, priority, tag)

    def count_support_lines(self):
        return sum(1 for index in self.entries if index != self.fault_index)

    def count_support_lines_excluding(self, ignored_tags):
        total = 0
        for index, entry in self.entries.items():
            if index == self.fault_index:
                continue
            tags = set(entry["tags"])
            if tags and tags.issubset(ignored_tags):
                continue
            total += 1
        return total

    def finalize(self, max_extra_lines):
        extra = [index for index in self.entries if index != self.fault_index]
        extra.sort(key=lambda index: (self.entries[index]["priority"], abs(index - self.fault_index), index))
        chosen = [self.fault_index] + extra[:max_extra_lines]
        chosen = sorted(set(chosen))
        rationale = {str(index + 1): self.entries[index]["tags"][:] for index in chosen}
        return chosen, rationale


def line_range(bounds, total_lines, fault_index):
    if bounds is not None:
        return list(range(bounds[0], bounds[1] + 1))
    start = max(0, fault_index - 25)
    end = min(total_lines - 1, fault_index + 25)
    return list(range(start, end + 1))


def nearby_indices(fault_index, total_lines, radius):
    start = max(0, fault_index - radius)
    end = min(total_lines - 1, fault_index + radius)
    return list(range(start, end + 1))


def select_lines_re(lines, fault_index, bounds, target_function):
    collector = CandidateCollector(lines, fault_index, bounds)
    search_indices = line_range(bounds, len(lines), fault_index)
    collector.add_nearest([index for index in search_indices if is_external_call_line(lines[index])], 10, "re_external_call", 2)
    collector.add_nearest(
        [
            index
            for index in search_indices
            if index != fault_index and is_state_update_line(lines[index]) and line_has_any(lines[index], _STATE_KEYWORDS)
        ],
        20,
        "re_state_update",
        3,
    )
    collector.add_nearest(
        [index for index in nearby_indices(fault_index, len(lines), 6) if is_guard_line(lines[index])],
        30,
        "re_guard_check",
        2,
    )
    if bounds is not None:
        collector.add(bounds[0], 50, "target_function_signature")
    return collector


def select_lines_tx(lines, fault_index, bounds, target_function):
    collector = CandidateCollector(lines, fault_index, bounds)
    search_indices = line_range(bounds, len(lines), fault_index)
    collector.add_nearest(
        [index for index in search_indices if "tx.origin" in lower_line(lines[index]) or "msg.sender" in lower_line(lines[index])],
        10,
        "tx_sender_check",
        3,
    )
    collector.add_nearest(
        [index for index in search_indices if is_guard_line(lines[index]) and line_has_any(lines[index], _AUTH_KEYWORDS)],
        20,
        "tx_auth_guard",
        3,
    )
    collector.add_nearest(
        [
            index
            for index in range(0, min(len(lines), fault_index + 1))
            if line_has_any(lines[index], _AUTH_KEYWORDS) and any(token in lower_line(lines[index]) for token in ("address", "mapping", "modifier"))
        ],
        30,
        "tx_role_definition",
        2,
    )
    if bounds is not None:
        collector.add(bounds[0], 50, "target_function_signature")
    return collector


def select_lines_tod(lines, fault_index, bounds, target_function):
    collector = CandidateCollector(lines, fault_index, bounds)
    search_indices = line_range(bounds, len(lines), fault_index)
    collector.add_nearest(
        [index for index in search_indices if line_has_any(lines[index], _TOD_KEYWORDS)],
        10,
        "tod_allowance_logic",
        4,
    )
    collector.add_nearest(
        [index for index in search_indices if is_state_update_line(lines[index]) and line_has_any(lines[index], _TOD_KEYWORDS)],
        20,
        "tod_state_update",
        3,
    )
    collector.add_nearest(
        [index for index in nearby_indices(fault_index, len(lines), 6) if is_guard_line(lines[index])],
        30,
        "tod_guard_check",
        2,
    )
    if bounds is not None:
        collector.add(bounds[0], 50, "target_function_signature")
    return collector


def extract_fault_identifiers(line):
    identifiers = []
    for token in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", clean_line(line)):
        lowered = token.lower()
        if lowered in _SOLIDITY_KEYWORDS:
            continue
        identifiers.append(lowered)
    return identifiers


def select_lines_io(lines, fault_index, bounds, target_function):
    collector = CandidateCollector(lines, fault_index, bounds)
    search_indices = line_range(bounds, len(lines), fault_index)
    collector.add_nearest([index for index in search_indices if is_arithmetic_line(lines[index])], 10, "io_arithmetic_line", 4)

    fault_identifiers = extract_fault_identifiers(lines[fault_index])
    for identifier in fault_identifiers[:4]:
        collector.add_nearest(
            [
                index
                for index in search_indices
                if index != fault_index and identifier in lower_line(lines[index]) and (is_state_update_line(lines[index]) or is_guard_line(lines[index]))
            ],
            20,
            "io_operand_support:" + identifier,
            1,
        )

    collector.add_nearest(
        [index for index in nearby_indices(fault_index, len(lines), 6) if is_guard_line(lines[index])],
        30,
        "io_guard_check",
        2,
    )
    if bounds is not None:
        collector.add(bounds[0], 50, "target_function_signature")
    return collector


def select_lines_ed(lines, fault_index, bounds, target_function):
    collector = CandidateCollector(lines, fault_index, bounds)
    search_indices = line_range(bounds, len(lines), fault_index)
    collector.add_nearest([index for index in search_indices if is_external_call_line(lines[index])], 10, "ed_external_call", 3)
    collector.add_nearest(
        [
            index
            for index in search_indices
            if is_guard_line(lines[index]) and (is_external_call_line(lines[index]) or "bool " in lower_line(lines[index]) or "!" in lower_line(lines[index]))
        ],
        20,
        "ed_return_check",
        3,
    )
    collector.add_nearest(
        [
            index
            for index in search_indices
            if index != fault_index and is_state_update_line(lines[index]) and line_has_any(lines[index], _STATE_KEYWORDS)
        ],
        30,
        "ed_state_dependency",
        3,
    )
    collector.add_nearest(
        [index for index in nearby_indices(fault_index, len(lines), 6) if is_guard_line(lines[index])],
        40,
        "ed_guard_check",
        2,
    )
    if bounds is not None:
        collector.add(bounds[0], 50, "target_function_signature")
    return collector


def build_selective_collector(lines, fault_index, target_function, vuln_type):
    bounds = find_function_bounds(lines, fault_index, target_function)
    if vuln_type == "RE":
        return select_lines_re(lines, fault_index, bounds, target_function), bounds
    if vuln_type == "TX":
        return select_lines_tx(lines, fault_index, bounds, target_function), bounds
    if vuln_type == "TOD":
        return select_lines_tod(lines, fault_index, bounds, target_function), bounds
    if vuln_type == "IO":
        return select_lines_io(lines, fault_index, bounds, target_function), bounds
    if vuln_type == "ED":
        return select_lines_ed(lines, fault_index, bounds, target_function), bounds
    return CandidateCollector(lines, fault_index, bounds), bounds


def build_serialized_context_from_indices(lines, indices):
    parts = []
    for index in indices:
        tokens = tokenize_code_fragment(lines[index])
        if tokens:
            parts.append(" ".join(tokens))
    return " <sep> ".join(parts)


def stringify_lines(lines, indices):
    return " || ".join("{}:{}".format(index + 1, clean_line(lines[index])) for index in indices if 0 <= index < len(lines))


def safe_csv_text(value):
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def build_context_record(sample_name, contract_path, original_context_path, row, match_method, lines):
    record = {
        "sample_name": sample_name,
        "contract_path": contract_path,
        "original_context_path": original_context_path,
        "metadata_row_id": "",
        "metadata_match_method": match_method,
        "vulnerability_type": "",
        "vulnerability_type_source": "",
        "fallback": 1,
        "fallback_reason": "",
        "fault_line_source": "",
        "fault_line_number": 0,
        "selected_line_numbers": [],
        "selected_line_tags": {},
        "original_context_lines": "",
        "selective_context_lines": "",
        "metadata_label_status": "",
        "metadata_label_confidence": "",
        "target_function": "",
        "context_summary": "",
        "notes": "",
    }
    default_fault_index, default_fault_source = find_fault_index(lines, {"fault_line": ""})
    if default_fault_index >= 0:
        record["fault_line_number"] = default_fault_index + 1
        record["fault_line_source"] = default_fault_source
        record["original_context_lines"] = stringify_lines(lines, get_original_context_indices(lines, default_fault_index))
    if row is None:
        record["fallback_reason"] = "metadata_unmatched"
        return record

    record["metadata_row_id"] = row.get("_row_id", "")
    record["metadata_label_status"] = row.get("label_status", "")
    record["metadata_label_confidence"] = row.get("label_confidence", "")
    record["target_function"] = row.get("target_function", "")
    record["notes"] = row.get("notes", "")

    vuln_type, vuln_source = choose_vulnerability_type(row)
    if not vuln_type:
        record["fallback_reason"] = "unusable_vulnerability_type"
        return record
    record["vulnerability_type"] = vuln_type
    record["vulnerability_type_source"] = vuln_source

    fault_index, fault_source = find_fault_index(lines, row)
    record["fault_line_source"] = fault_source
    if fault_index < 0:
        record["fallback_reason"] = "fault_line_missing"
        return record

    record["fault_line_number"] = fault_index + 1
    original_indices = get_original_context_indices(lines, fault_index)
    record["original_context_lines"] = stringify_lines(lines, original_indices)
    collector, bounds = build_selective_collector(lines, fault_index, row.get("target_function", ""), vuln_type)

    useful_support = collector.count_support_lines_excluding({"target_function_signature"})
    if useful_support <= 0:
        record["fallback_reason"] = "too_little_signal"
        return record

    selected_indices, rationale = collector.finalize(DEFAULT_MAX_EXTRA_LINES)
    serialized = build_serialized_context_from_indices(lines, selected_indices)
    if not serialized:
        record["fallback_reason"] = "tokenization_failed"
        return record

    record["fallback"] = 0
    record["fallback_reason"] = ""
    record["selected_line_numbers"] = [index + 1 for index in selected_indices]
    record["selected_line_tags"] = rationale
    record["selective_context_lines"] = stringify_lines(lines, selected_indices)
    record["context_summary"] = "bounds={}".format(bounds if bounds is not None else "none")
    return record, serialized


def derive_output_dir(original_code_dir, split_name):
    base_dir = os.path.dirname(original_code_dir)
    folder_name = os.path.basename(original_code_dir.rstrip("/\\"))
    if split_name == "train":
        base_dir = os.path.dirname(original_code_dir.rstrip("/\\"))
    return os.path.join(base_dir, folder_name + "-selective")


def derive_log_dir(dataset_path, split_name):
    if split_name == "train":
        return os.path.join(dataset_path, "selective_context_logs", "train")
    if split_name == "pretrain":
        return os.path.join(dataset_path, "pretrain", "selective_context_logs")
    if split_name == "validation":
        return os.path.join(dataset_path, "validation", "selective_context_logs")
    return os.path.join(dataset_path, "selective_context_logs", split_name)


def build_original_context_fallback(original_context_path):
    with open(original_context_path, "r", encoding="utf-8") as f:
        return f.read().strip()


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            f.write("\n")


def write_csv(path, rows):
    fieldnames = [
        "sample_name",
        "contract_path",
        "original_context_path",
        "metadata_row_id",
        "metadata_match_method",
        "vulnerability_type",
        "vulnerability_type_source",
        "fallback",
        "fallback_reason",
        "fault_line_source",
        "fault_line_number",
        "selected_line_numbers",
        "selected_line_tags",
        "original_context_lines",
        "selective_context_lines",
        "metadata_label_status",
        "metadata_label_confidence",
        "target_function",
        "context_summary",
        "notes",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: safe_csv_text(row.get(key, "")) for key in fieldnames})


def prepare_context_directory(dataset_path, original_code_dir, contract_dir, split_name, context_mode="original", metadata_csv="", logger=None):
    if context_mode == "original":
        return original_code_dir

    dataset_path = os.path.abspath(dataset_path)
    original_code_dir = os.path.abspath(original_code_dir)
    contract_dir = os.path.abspath(contract_dir)

    output_dir = derive_output_dir(original_code_dir, split_name)
    log_dir = derive_log_dir(dataset_path, split_name)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    metadata_lookup = get_metadata_lookup(dataset_path, metadata_csv)
    metadata_csv_path = metadata_lookup.csv_path

    if metadata_csv_path:
        emit_log(logger, "[selective_context] split={} metadata_csv={}".format(split_name, metadata_csv_path))
    else:
        emit_log(logger, "[selective_context] split={} metadata_csv=missing -> all samples fallback to original".format(split_name))

    rows = []
    match_counter = Counter()
    fallback_counter = Counter()
    type_counter = Counter()

    sample_names = sorted(name for name in os.listdir(original_code_dir) if name.endswith(".sol"))
    for sample_name in sample_names:
        original_context_path = os.path.join(original_code_dir, sample_name)
        contract_path = os.path.join(contract_dir, sample_name)
        output_path = os.path.join(output_dir, sample_name)

        row = None
        match_method = "metadata_missing"
        if metadata_lookup.loaded:
            row, match_method = metadata_lookup.match(sample_name, contract_path, original_context_path)
        match_counter[match_method] += 1

        record = None
        serialized_context = ""
        if not os.path.isfile(contract_path):
            record = {
                "sample_name": sample_name,
                "contract_path": contract_path,
                "original_context_path": original_context_path,
                "metadata_row_id": row.get("_row_id", "") if row is not None else "",
                "metadata_match_method": match_method,
                "vulnerability_type": "",
                "vulnerability_type_source": "",
                "fallback": 1,
                "fallback_reason": "contract_missing",
                "fault_line_source": "",
                "fault_line_number": 0,
                "selected_line_numbers": [],
                "selected_line_tags": {},
                "original_context_lines": "",
                "selective_context_lines": "",
                "metadata_label_status": row.get("label_status", "") if row is not None else "",
                "metadata_label_confidence": row.get("label_confidence", "") if row is not None else "",
                "target_function": row.get("target_function", "") if row is not None else "",
                "context_summary": "",
                "notes": row.get("notes", "") if row is not None else "",
            }
        else:
            with open(contract_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            built = build_context_record(sample_name, contract_path, original_context_path, row, match_method, lines)
            if isinstance(built, tuple):
                record, serialized_context = built
            else:
                record = built
            if not metadata_lookup.loaded and record["fallback_reason"] == "metadata_unmatched":
                record["fallback_reason"] = "metadata_missing"

        if not serialized_context:
            serialized_context = build_original_context_fallback(original_context_path)
            record["fallback"] = 1

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(serialized_context)
            if serialized_context and not serialized_context.endswith("\n"):
                f.write("\n")

        rows.append(record)
        if record["fallback"]:
            fallback_counter[record["fallback_reason"] or "fallback_unknown"] += 1
        if record["vulnerability_type"]:
            type_counter[record["vulnerability_type"]] += 1

    write_jsonl(os.path.join(log_dir, "samples.jsonl"), rows)
    write_csv(os.path.join(log_dir, "samples.csv"), rows)
    with open(os.path.join(log_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "split": split_name,
                "dataset_path": dataset_path,
                "original_code_dir": original_code_dir,
                "output_dir": output_dir,
                "contract_dir": contract_dir,
                "metadata_csv": metadata_csv_path,
                "sample_count": len(rows),
                "match_counts": dict(match_counter),
                "fallback_counts": dict(fallback_counter),
                "vulnerability_type_counts": dict(type_counter),
            },
            f,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )

    emit_log(
        logger,
        "[selective_context] split={} samples={} output_dir={} matches={} fallbacks={}".format(
            split_name,
            len(rows),
            output_dir,
            dict(match_counter),
            dict(fallback_counter),
        ),
    )
    return output_dir
