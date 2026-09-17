import hashlib
import json
import os
import warnings


DEFAULT_SLITHER_IMAGE = "sha256:1e2685153d1ba30dc3cc400ec420501e8d0b29b801484c71acb51552597891c2"
CONTEXT_VERSION = 1
DEFAULT_RULE_VERSION = "v1"
SUPPORTED_RULE_VERSIONS = ("v1", "v3")
GRAPH_SCHEMA_VERSION = 2
BACKEND = "slither_docker_0.6.1"
SOLC_VERSION = "0.4.25"


def canonical_context_mode(mode):
    return "selective" if mode == "selective_v1" else mode


def build_context_config(mode, token_budget=64, max_nodes=8, max_hops=2,
                         fallback="selective_v1", slither_image=DEFAULT_SLITHER_IMAGE,
                         rule_version=DEFAULT_RULE_VERSION):
    mode = canonical_context_mode(mode)
    config = {
        "mode": mode,
        "version": CONTEXT_VERSION,
    }
    if mode == "evidence_graph":
        if rule_version not in SUPPORTED_RULE_VERSIONS:
            raise ValueError("unsupported evidence graph rule version: {}".format(rule_version))
        config.update({
            "backend": BACKEND,
            "slither_image": slither_image,
            "solc_version": SOLC_VERSION,
            "token_budget": int(token_budget),
            "max_nodes": int(max_nodes),
            "max_hops": int(max_hops),
            "fallback": fallback,
            "rule_version": rule_version,
            "graph_schema_version": GRAPH_SCHEMA_VERSION,
        })
    payload = json.dumps(config, sort_keys=True, separators=(",", ":"))
    config["config_hash"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return config


def evidence_directory(original_code_dir, context_config):
    folder = os.path.basename(original_code_dir.rstrip("/\\"))
    suffix = "evidence-graph-b{}-n{}-h{}-{}-{}".format(
        context_config["token_budget"],
        context_config["max_nodes"],
        context_config["max_hops"],
        context_config["rule_version"],
        context_config["config_hash"][:8],
    )
    return os.path.join(os.path.dirname(original_code_dir.rstrip("/\\")), folder + "-" + suffix)


def validate_checkpoint_context(checkpoint, current_config, logger=None, purpose="resume",
                                allow_legacy_evidence=False):
    saved = checkpoint.get("context_config")
    if saved is None:
        if current_config.get("mode") == "evidence_graph" and not allow_legacy_evidence:
            raise ValueError(
                "The checkpoint has no context_config and cannot be verified for evidence_graph {}. "
                "Use a matching evidence_graph checkpoint, start training with the 'fresh' positional "
                "argument, or explicitly pass --allow-legacy-context-checkpoint if this reuse is intentional."
                .format(purpose)
            )
        message = (
            "Legacy checkpoint has no context_config; its preprocessing settings cannot be "
            "verified. Loading remains supported for backward compatibility."
        )
        if logger is not None:
            logger.warning(message)
        else:
            warnings.warn(message)
        return
    if saved != current_config:
        raise ValueError(
            "Checkpoint context_config differs from the requested context during {}. "
            "saved={} requested={}".format(
                purpose,
                json.dumps(saved, sort_keys=True),
                json.dumps(current_config, sort_keys=True),
            )
        )
