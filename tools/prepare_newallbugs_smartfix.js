#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const SUPPORTED_TYPES = new Set(["IO", "RE", "TX"]);
const TYPE_TO_DATASET = { IO: "io", RE: "re", TX: "tx" };
const TYPE_TO_DIR = { IO: "cve", RE: "reentrancy", TX: "txorigin" };
const TYPE_TO_TAG = { IO: "<IO_VUL>", RE: "<RE_VUL>", TX: "<TX_VUL>" };

const SOLC_SUPPORTED = [
  "0.4.11", "0.4.16", "0.4.17", "0.4.18", "0.4.19", "0.4.20", "0.4.21",
  "0.4.23", "0.4.24", "0.4.25", "0.4.26",
  "0.5.0", "0.5.1", "0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6",
  "0.5.7", "0.5.9", "0.5.10", "0.5.11", "0.5.12", "0.5.13",
  "0.5.14", "0.5.15", "0.5.16", "0.5.17",
  "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6",
  "0.6.7", "0.6.8", "0.6.9", "0.6.10", "0.6.11", "0.6.12",
  "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6",
  "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6",
  "0.8.7", "0.8.8", "0.8.9", "0.8.10", "0.8.11", "0.8.12",
  "0.8.13", "0.8.14", "0.8.15", "0.8.16", "0.8.17",
];

function parseArgs(argv) {
  const args = {
    force: false,
    artifactRoot: path.resolve(__dirname, ".."),
    datasetRoot: "",
    outputRoot: "",
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--force") {
      args.force = true;
    } else if (arg === "--artifact-root") {
      args.artifactRoot = path.resolve(argv[++i]);
    } else if (arg === "--dataset-root") {
      args.datasetRoot = path.resolve(argv[++i]);
    } else if (arg === "--output-root") {
      args.outputRoot = path.resolve(argv[++i]);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  if (!args.datasetRoot) {
    args.datasetRoot = path.resolve(
      args.artifactRoot,
      "..",
      "rlrep-vulnerability-aware-context",
      "dataset_vul",
      "newALLBUGS"
    );
  }
  if (!args.outputRoot) {
    args.outputRoot = path.resolve(args.artifactRoot, "newallbugs_smartfix");
  }
  return args;
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];
    if (inQuotes) {
      if (ch === '"' && next === '"') {
        field += '"';
        i += 1;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (ch !== "\r") {
      field += ch;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  const header = rows.shift();
  const cleanHeader = header.map((key) => key.replace(/^\uFEFF/, ""));
  return rows.filter((r) => r.length > 1).map((values) => {
    const obj = {};
    cleanHeader.forEach((key, idx) => {
      obj[key] = values[idx] || "";
    });
    return obj;
  });
}

function csvEscape(value) {
  const s = String(value == null ? "" : value);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function writeCsv(file, rows, header) {
  const lines = [header.map(csvEscape).join(",")];
  rows.forEach((row) => {
    lines.push(header.map((key) => csvEscape(row[key] || "")).join(","));
  });
  fs.writeFileSync(file, `${lines.join("\n")}\n`, "utf8");
}

function compareVersion(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i += 1) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
}

function sameMinor(a, b) {
  const pa = a.split(".");
  const pb = b.split(".");
  return pa[0] === pb[0] && pa[1] === pb[1];
}

function firstSupportedAtLeast(base, sameMinorOnly) {
  return SOLC_SUPPORTED.find((candidate) => {
    if (compareVersion(candidate, base) < 0) return false;
    return sameMinorOnly ? sameMinor(candidate, base) : true;
  }) || "";
}

function inferSolcVersion(source) {
  const match = source.match(/pragma\s+solidity\s+([^;]+);/);
  if (!match) {
    return { version: "0.4.25", pragma: "", note: "default_no_pragma" };
  }
  const pragma = match[1].replace(/\s+/g, " ").trim();
  const versions = Array.from(pragma.matchAll(/\d+\.\d+\.\d+/g)).map((m) => m[0]);
  if (versions.length === 0) {
    return { version: "0.4.25", pragma, note: "default_unparsed_pragma" };
  }
  const base = versions[0];
  const exact = /^=?\s*\d+\.\d+\.\d+$/.test(pragma);
  if (exact) {
    return {
      version: SOLC_SUPPORTED.includes(base) ? base : "",
      pragma,
      note: SOLC_SUPPORTED.includes(base) ? "exact" : `unsupported_exact_${base}`,
    };
  }
  if (pragma.startsWith("^")) {
    const version = firstSupportedAtLeast(base, base.startsWith("0."));
    return { version, pragma, note: version ? "caret" : `unsupported_caret_${base}` };
  }
  if (pragma.includes(">=")) {
    const version = firstSupportedAtLeast(base, false);
    return { version, pragma, note: version ? "range_min" : `unsupported_range_${base}` };
  }
  const fallback = firstSupportedAtLeast(base, base.startsWith("0."));
  return { version: fallback, pragma, note: fallback ? "fallback" : `unsupported_${base}` };
}

function parseContracts(lines) {
  const contracts = [];
  let pending = null;
  let depth = 0;
  let seenOpen = false;
  const re = /\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)\b/;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (!pending) {
      const m = line.match(re);
      if (m) {
        pending = { kind: m[1], name: m[2], start: i + 1 };
        depth = 0;
        seenOpen = false;
      }
    }
    if (pending) {
      const opens = (line.match(/{/g) || []).length;
      const closes = (line.match(/}/g) || []).length;
      if (opens > 0) seenOpen = true;
      depth += opens - closes;
      if (seenOpen && depth <= 0) {
        contracts.push({ ...pending, end: i + 1 });
        pending = null;
        depth = 0;
        seenOpen = false;
      }
    }
  }
  if (pending) {
    contracts.push({ ...pending, end: lines.length });
  }
  return contracts;
}

function inferMainName(source, faultLine) {
  const lines = source.split(/\r?\n/);
  const contracts = parseContracts(lines);
  const containing = contracts.filter((c) => c.start <= faultLine && faultLine <= c.end);
  const concrete = containing.find((c) => c.kind === "contract");
  if (concrete) return { mainName: concrete.name, note: "contains_fault_line" };
  if (containing[0]) {
    const after = contracts.find((c) => c.kind === "contract" && c.start > faultLine);
    if (after) return { mainName: after.name, note: `after_${containing[0].kind}_fault_line` };
  }
  const before = contracts.filter((c) => c.kind === "contract" && c.start <= faultLine).pop();
  if (before) return { mainName: before.name, note: "nearest_contract_before_fault" };
  const first = contracts.find((c) => c.kind === "contract") || contracts[0];
  if (first) return { mainName: first.name, note: "first_definition_fallback" };
  return { mainName: "", note: "no_contract_found" };
}

function insertTag(source, faultLine, tag) {
  const hasCrLf = source.includes("\r\n");
  const newline = hasCrLf ? "\r\n" : "\n";
  const lines = source.split(/\r?\n/);
  if (faultLine < 1 || faultLine > lines.length) {
    throw new Error(`fault_line_no ${faultLine} outside source length ${lines.length}`);
  }
  const idx = faultLine - 1;
  if (!lines[idx].includes(tag)) {
    lines[idx] = `${lines[idx]} /* ${tag} */`;
  }
  return lines.join(newline);
}

function ensureCleanOutput(outputRoot, artifactRoot, force) {
  const resolvedOutput = path.resolve(outputRoot);
  const resolvedArtifact = path.resolve(artifactRoot);
  if (!resolvedOutput.startsWith(resolvedArtifact + path.sep)) {
    throw new Error(`Refusing to write outside artifact root: ${resolvedOutput}`);
  }
  if (fs.existsSync(resolvedOutput)) {
    if (!force) {
      throw new Error(`Output exists: ${resolvedOutput}. Re-run with --force to replace it.`);
    }
    fs.rmSync(resolvedOutput, { recursive: true, force: true });
  }
  fs.mkdirSync(resolvedOutput, { recursive: true });
}

function main() {
  const args = parseArgs(process.argv);
  const labelCsv = path.join(args.datasetRoot, "eval", "validation_vulnerability_type_final_labels_20260904.csv");
  const contractDir = path.join(args.datasetRoot, "validation", "contract");
  if (!fs.existsSync(labelCsv)) throw new Error(`Missing label CSV: ${labelCsv}`);
  if (!fs.existsSync(contractDir)) throw new Error(`Missing contract dir: ${contractDir}`);

  ensureCleanOutput(args.outputRoot, args.artifactRoot, args.force);
  const benchRoot = path.join(args.outputRoot, "benchmarks");
  Object.values(TYPE_TO_DIR).forEach((dir) => fs.mkdirSync(path.join(benchRoot, dir), { recursive: true }));

  const labels = parseCsv(fs.readFileSync(labelCsv, "utf8"));
  const metaRows = [];
  const supportedRows = [];
  const skippedRows = [];
  const issues = [];
  let actualOrder = 1;

  labels.forEach((row) => {
    const sampleName = row.sample_name;
    const type = (row.final_dataset_type || "").trim().toUpperCase();
    if (!SUPPORTED_TYPES.has(type)) {
      skippedRows.push({ sample_name: sampleName, final_dataset_type: type, reason: "unsupported_type" });
      return;
    }
    const srcFile = path.join(contractDir, `${sampleName}.sol`);
    if (!fs.existsSync(srcFile)) {
      issues.push({ sample_name: sampleName, final_dataset_type: type, issue: "source_missing", detail: srcFile });
      return;
    }
    const source = fs.readFileSync(srcFile, "utf8");
    const faultLine = Number.parseInt(row.fault_line_no, 10);
    if (!Number.isInteger(faultLine) || faultLine <= 0) {
      issues.push({ sample_name: sampleName, final_dataset_type: type, issue: "invalid_fault_line", detail: row.fault_line_no });
      return;
    }
    const solc = inferSolcVersion(source);
    if (!solc.version) {
      issues.push({ sample_name: sampleName, final_dataset_type: type, issue: "unsupported_solc", detail: solc.note });
      return;
    }
    const main = inferMainName(source, faultLine);
    if (!main.mainName) {
      issues.push({ sample_name: sampleName, final_dataset_type: type, issue: "main_contract_missing", detail: main.note });
      return;
    }
    let tagged;
    try {
      tagged = insertTag(source, faultLine, TYPE_TO_TAG[type]);
    } catch (err) {
      issues.push({ sample_name: sampleName, final_dataset_type: type, issue: "tag_insert_failed", detail: err.message });
      return;
    }
    const dataset = TYPE_TO_DATASET[type];
    const destDir = path.join(benchRoot, TYPE_TO_DIR[type]);
    const destFile = path.join(destDir, `${sampleName}.sol`);
    fs.writeFileSync(destFile, tagged, "utf8");

    const lineCount = source.split(/\r?\n/).length;
    const addressMatch = sampleName.match(/0x[a-fA-F0-9]{40}/);
    const address = addressMatch ? addressMatch[0] : "";
    metaRows.push({
      dataset,
      id: sampleName,
      duplicate_of: "",
      actual_order: actualOrder,
      main_name: main.mainName,
      original_loc: "",
      loc: lineCount,
      address,
      compiler_version: `v${solc.version}+newallbugs`,
      original_compiler_version: solc.pragma || `v${solc.version}+newallbugs`,
      is_multiple: "",
      fail: "",
      source: "newALLBUGS-validation",
    });
    supportedRows.push({
      sample_name: sampleName,
      final_dataset_type: type,
      smartfix_dataset: dataset,
      smartfix_dir: TYPE_TO_DIR[type],
      fault_line_no: faultLine,
      target_function: row.target_function || "",
      main_name: main.mainName,
      main_name_note: main.note,
      compiler_version: solc.version,
      pragma: solc.pragma,
      solc_note: solc.note,
      output_file: path.relative(args.outputRoot, destFile).replace(/\\/g, "/"),
    });
    actualOrder += 1;
  });

  const metaHeader = [
    "dataset", "id", "duplicate_of", "actual_order", "main_name", "original_loc", "loc",
    "address", "compiler_version", "original_compiler_version", "is_multiple", "fail", "source",
  ];
  writeCsv(path.join(benchRoot, "mix-meta.csv"), metaRows, metaHeader);
  writeCsv(path.join(args.outputRoot, "supported_samples.csv"), supportedRows, [
    "sample_name", "final_dataset_type", "smartfix_dataset", "smartfix_dir", "fault_line_no",
    "target_function", "main_name", "main_name_note", "compiler_version", "pragma", "solc_note", "output_file",
  ]);
  writeCsv(path.join(args.outputRoot, "skipped_samples.csv"), skippedRows, [
    "sample_name", "final_dataset_type", "reason",
  ]);
  writeCsv(path.join(args.outputRoot, "preparation_issues.csv"), issues, [
    "sample_name", "final_dataset_type", "issue", "detail",
  ]);

  const countByType = supportedRows.reduce((acc, row) => {
    acc[row.final_dataset_type] = (acc[row.final_dataset_type] || 0) + 1;
    return acc;
  }, {});
  const readme = `# newALLBUGS SmartFix Benchmark

Generated from:

- ${path.relative(args.artifactRoot, labelCsv).replace(/\\/g, "/")}
- ${path.relative(args.artifactRoot, contractDir).replace(/\\/g, "/")}

This directory is an adapter for running the full SmartFix configuration on the
commonly supported vulnerability families only: IO, RE, and TX.

## Counts

- IO: ${countByType.IO || 0}
- RE: ${countByType.RE || 0}
- TX: ${countByType.TX || 0}
- Total supported: ${supportedRows.length}
- Skipped unsupported labels: ${skippedRows.length}
- Preparation issues: ${issues.length}

## Run

From the SmartFix-Artifact directory on a Linux machine with Docker:

\`\`\`bash
docker build -f Dockerfile.newallbugs -t smartfix-newallbugs --build-arg CORE=32 .

docker run --rm -it \\
  -v "$PWD/fix_result:/home/opam/fix_result" \\
  -v "$PWD/newallbugs_smartfix/benchmarks:/home/opam/benchmarks:ro" \\
  smartfix-newallbugs python3 fix_experiment/scripts/do_all_smartfix.py \\
    --meta_csv /home/opam/benchmarks/mix-meta.csv \\
    --dataset io,re,tx \\
    --process 32
\`\`\`

Adjust \`CORE\` and \`--process\` to the number of CPU cores you want to use.
This uses the full SmartFix/Ours mode from the artifact, not Basic or Online
ablation variants.

If the server Docker daemon has a broken Docker Hub mirror and cannot pull
\`ocaml/opam:ubuntu-20.04\`, use an explicit registry mirror for the base image:

\`\`\`bash
docker build -f Dockerfile.newallbugs -t smartfix-newallbugs \\
  --build-arg CORE=32 \\
  --build-arg BASE_IMAGE=docker.m.daocloud.io/ocaml/opam:ubuntu-20.04 .
\`\`\`
`;
  fs.writeFileSync(path.join(args.outputRoot, "README.md"), readme, "utf8");

  const runScript = `#!/usr/bin/env bash
set -euo pipefail

CORES="\${1:-32}"
IMAGE="\${SMARTFIX_IMAGE:-smartfix-newallbugs}"

docker run --rm -it \\
  -v "$PWD/fix_result:/home/opam/fix_result" \\
  -v "$PWD/newallbugs_smartfix/benchmarks:/home/opam/benchmarks:ro" \\
  "$IMAGE" python3 fix_experiment/scripts/do_all_smartfix.py \\
    --meta_csv /home/opam/benchmarks/mix-meta.csv \\
    --dataset io,re,tx \\
    --process "$CORES"
`;
  fs.writeFileSync(path.join(args.outputRoot, "run_smartfix_newallbugs.sh"), runScript, "utf8");

  const summary = {
    outputRoot: args.outputRoot,
    supportedTotal: supportedRows.length,
    skippedTotal: skippedRows.length,
    issueTotal: issues.length,
    countByType,
  };
  fs.writeFileSync(path.join(args.outputRoot, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  console.log(JSON.stringify(summary, null, 2));
}

main();
