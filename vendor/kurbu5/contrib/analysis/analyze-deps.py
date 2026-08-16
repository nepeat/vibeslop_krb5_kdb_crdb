#!/usr/bin/env python3
"""
Cargo workspace dependency analyser.

Usage:
    python3 contrib/analyze-deps.py [--json] [--verbose]
    python3 contrib/analyze-deps.py --who-needs NAME
    python3 contrib/analyze-deps.py --why NAME
    python3 contrib/analyze-deps.py --trace-feature DEP FEATURE

Requires: cargo (any recent version), run from the workspace root.

What it does:
  1. Runs `cargo metadata` to get the full resolved dependency graph.
  2. Discovers workspace members and their names from Cargo.toml.
  3. Classifies every package as production / dev / build.
  4. Reports per-crate dependency counts.
  5. Finds duplicate package versions.
  6. Finds packages exclusively in dev/bench/build, grouped by the
     direct dev dependency that introduces them.
  7. Analyses features requested for each direct dependency vs the
     resolved set and the available set, flagging redundant defaults,
     over-wide feature sets, and cross-crate feature leakage.
     Detects "no-op" suggestions where the same features are already mandated
     by non-workspace transitive deps (e.g. reqwest, hickory-proto) so that
     setting `default-features = false` would not change the compiled binary.
  8. Derives all suggestions from the analysis — no workspace-specific
     names or counts are hardcoded in this script.

Investigation tools (skip the full report):
  --who-needs NAME          Show direct dependents of NAME in the dep graph.
  --why NAME                Trace NAME back to workspace members via all paths,
                            annotating each hop with its dep-kind (like
                            `cargo tree --invert` but with prod/dev/build labels).
  --trace-feature DEP FEAT  Find every package that explicitly requests FEAT
                            from DEP, then trace each one back to workspace
                            members to show whether the feature is pulled in via
                            production or dev/build paths.
"""

import json
import os
import subprocess
import sys
import argparse
from collections import defaultdict, deque


# ── helpers ──────────────────────────────────────────────────────────────────

def cargo_metadata():
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("ERROR: cargo metadata failed:", result.stderr[:500], file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def _parse_cargo_tree_labels(stdout: str) -> set:
    """
    Parse the output of a ``cargo tree --prefix none --format {p}`` run into
    a set of ``"name vX.Y.Z"`` strings, stripping the ``(*)`` deduplication
    marker and any local path suffix appended for workspace members.
    """
    labels: set = set()
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.endswith(" (*)"):
            stripped = stripped[:-4]
        if " (" in stripped and stripped.endswith(")"):
            paren_start = stripped.rfind(" (")
            inner = stripped[paren_start + 2:-1]
            if inner.startswith("/") or inner.startswith("C:\\") or inner.startswith("C:/"):
                stripped = stripped[:paren_start]
        if stripped:
            labels.add(stripped)
    return labels


def _cargo_tree_prod_labels() -> set:
    """
    Run ``cargo tree --prefix none --edges no-dev --workspace --locked`` and
    return the set of ``"name vX.Y.Z"`` labels that cargo actually compiles on
    this platform with the current feature selection.

    cargo metadata's resolve graph includes optional deps that are locked in
    Cargo.lock but NOT activated by the current feature set (e.g. the ``rkyv``
    feature of ``rust_decimal``), as well as platform-conditional deps for
    other targets (e.g. ``windows-sys`` on Linux).  ``cargo tree`` honours
    both constraints and is therefore the reliable source of truth.

    ``--locked`` ensures we analyse exactly what Cargo.lock describes, not a
    fresh resolution that might differ from what was actually built.

    Returns an empty set on any error so callers can fall back gracefully.
    """
    print("Running `cargo tree --edges no-dev`…", file=sys.stderr)
    r = subprocess.run(
        ["cargo", "tree", "--prefix", "none", "--edges", "no-dev",
         "--workspace", "--locked", "--format", "{p}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  cargo tree failed (exit {r.returncode}):", file=sys.stderr)
        if r.stderr:
            print(r.stderr[:500], file=sys.stderr)
        return set()
    return _parse_cargo_tree_labels(r.stdout)


def _cargo_tree_compiled_duplicates() -> set:
    """
    Run ``cargo tree --duplicates --edges no-dev --workspace --locked`` and
    return the set of package *names* that appear with genuinely *different*
    compiled versions on this platform.

    ``cargo tree --duplicates`` lists every package that is resolved more than
    once in the dependency graph.  That includes two distinct cases:

    * **True version conflicts** — different version numbers compiled for the
      same target (e.g. ``syn v1`` and ``syn v2``).  These may increase binary
      size or require ``[patch.crates-io]`` to unify.
    * **Build-host/target splits** — the *same* version compiled twice because
      one copy is needed by a build-script dep chain (compiled for the build
      host) and another by a regular production dep (compiled for the target).
      This is normal Cargo behaviour and harmless.

    Only package names with more than one *distinct version string* in the
    ``cargo tree --duplicates`` output are returned, so build-host/target
    splits (same version) are excluded.

    Returns an empty set on any error so callers can fall back gracefully.
    """
    print("Running `cargo tree --duplicates`…", file=sys.stderr)
    r = subprocess.run(
        ["cargo", "tree", "--duplicates", "--prefix", "none",
         "--edges", "no-dev", "--workspace", "--locked", "--format", "{p}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  cargo tree --duplicates failed (exit {r.returncode}):", file=sys.stderr)
        if r.stderr:
            print(r.stderr[:500], file=sys.stderr)
        return set()
    name_versions: dict = defaultdict(set)
    for label in _parse_cargo_tree_labels(r.stdout):
        # label is "name vX.Y.Z"; split on the last space to separate version.
        parts = label.rsplit(" ", 1)
        if len(parts) == 2 and parts[1].startswith("v"):
            name_versions[parts[0]].add(parts[1])
    return {name for name, vers in name_versions.items() if len(vers) > 1}


def workspace_name(meta: dict) -> str:
    return os.path.basename(meta.get("workspace_root", "workspace")) or "workspace"


def expand_features(pkg_feature_map: dict, requested: set) -> set:
    """
    Transitively expand a set of feature names using the package's feature
    definition map.  Skips `dep:crate` optional-dep activations and
    `crate/feature` cross-crate feature forwards (those are handled by Cargo
    itself and don't appear as plain feature names in the resolved set).
    """
    expanded = set()
    queue = list(requested)
    while queue:
        feat = queue.pop()
        if feat in expanded:
            continue
        expanded.add(feat)
        for sub in pkg_feature_map.get(feat, []):
            if sub.startswith("dep:") or "/" in sub:
                continue
            if sub not in expanded:
                queue.append(sub)
    return expanded


def find_transitive_activators(
        dep_id: str, dep_pkg: dict, features_to_check: frozenset,
        excluding_ids: set, node_deps: dict, packages: dict,
        id_to_label: dict) -> dict:
    """
    Find non-excluded packages in the resolve graph that directly depend on
    dep_id (via a production edge) and activate at least one of
    features_to_check on it.

    Returns {package_label: sorted_feature_overlap} for non-empty overlaps.

    Use this to detect when a "default features add" suggestion would be a
    no-op: if non-workspace transitive deps (e.g. cookie_store, hickory-proto)
    already mandate the same features, disabling defaults on a workspace
    member's direct dep declaration changes nothing in the compiled binary.
    """
    if not features_to_check:
        return {}
    dep_feat_map  = dep_pkg.get("features", {})
    dep_name_norm = dep_pkg["name"].replace("-", "_")
    activators: dict = {}
    for pid, deps in node_deps.items():
        if pid in excluding_ids:
            continue
        if dep_id not in deps.get("prod", set()):
            continue
        pkg = packages.get(pid)
        if not pkg:
            continue
        for dep_decl in pkg.get("dependencies", []):
            if dep_decl["name"].replace("-", "_") != dep_name_norm:
                continue
            explicit  = frozenset(dep_decl.get("features", []))
            uses_def  = dep_decl.get("uses_default_features", True)
            dep_defs  = frozenset(dep_feat_map.get("default", []))
            activated = expand_features(dep_feat_map, explicit)
            if uses_def:
                activated |= expand_features(dep_feat_map, dep_defs)
            overlap = activated & features_to_check
            if overlap:
                label = id_to_label.get(pid, pid)
                activators[label] = sorted(overlap)
    return activators


def _transitive(node_deps: dict, root_ids: set, dep_key: str) -> set:
    """Collect all packages transitively reachable from root_ids via dep_key edges."""
    visited, queue = set(), list(root_ids)
    while queue:
        cur = queue.pop()
        if cur in visited:
            continue
        visited.add(cur)
        for nxt in node_deps.get(cur, {}).get(dep_key, set()):
            if nxt not in visited:
                queue.append(nxt)
    return visited - root_ids


def _is_publish_false(pkg: dict) -> bool:
    """Return True if the package has ``publish = false`` in its Cargo.toml.

    ``cargo metadata`` represents ``publish = false`` as ``"publish": []``.
    Any other value (``null`` for the default, or a list of registry names)
    means the package is publishable.  Warn if we see an unexpected value so
    that future Cargo metadata format changes don't silently miscategorise
    packages.
    """
    publish = pkg.get("publish")
    if publish is None or (isinstance(publish, list) and len(publish) > 0):
        return False
    if publish == []:
        return True
    print(
        f"  warning: unexpected 'publish' value {publish!r} for {pkg.get('name')}; "
        "treating as publishable",
        file=sys.stderr,
    )
    return False


# ── core dependency graph analysis ───────────────────────────────────────────

def analyse(meta: dict) -> dict:
    workspace_members = set(meta["workspace_members"])
    packages = {p["id"]: p for p in meta["packages"]}
    id_to_label = {p["id"]: f"{p['name']} v{p['version']}" for p in meta["packages"]}

    # Workspace members with `publish = false` are internal tooling (fuzzers,
    # benchmarks, CLI tools) — not shipped as library artifacts.  Their
    # production dependencies are classified as tooling-reachable rather than
    # workspace-production-reachable so they don't inflate the "prod" counts.
    tooling_members = frozenset(
        mid for mid in workspace_members
        if _is_publish_false(packages[mid])
    )
    library_members = workspace_members - tooling_members

    # ── 1. Dependency graph from resolve section ──────────────────────────────
    node_deps: dict = {}  # id → {prod: set, dev: set, build: set}
    for node in meta["resolve"]["nodes"]:
        nid = node["id"]
        node_deps[nid] = {"prod": set(), "dev": set(), "build": set()}
        for dep in node.get("deps", []):
            dep_id = dep["pkg"]
            for dk in dep.get("dep_kinds", [{"kind": None}]):
                kind = dk.get("kind")
                if kind is None:
                    node_deps[nid]["prod"].add(dep_id)
                elif kind == "dev":
                    node_deps[nid]["dev"].add(dep_id)
                elif kind == "build":
                    node_deps[nid]["build"].add(dep_id)

    def trans(root_ids, dep_key):
        return _transitive(node_deps, root_ids, dep_key)

    # ── 2. Reachability sets ──────────────────────────────────────────────────
    # Library members drive the workspace "production" footprint.
    prod_roots = set()
    for mid in library_members:
        prod_roots |= node_deps.get(mid, {}).get("prod", set())
    prod_reachable = trans(prod_roots, "prod") | prod_roots

    # Tooling-only reachable: deps of publish=false members not already in prod.
    tooling_roots = set()
    for mid in tooling_members:
        tooling_roots |= node_deps.get(mid, {}).get("prod", set())
    tooling_reachable = (trans(tooling_roots, "prod") | tooling_roots) - prod_reachable

    # ── 2b. Compiled-on-this-platform set (cargo tree as ground truth) ────────
    # cargo metadata includes optional deps that are locked but not activated by
    # the current features, and platform-conditional deps for other targets.
    # Use `cargo tree` to build a "truly compiled" subset of prod_reachable.
    _compiled_labels = _cargo_tree_prod_labels()
    if _compiled_labels:
        compiled_ids = frozenset(
            pid for pid in prod_reachable
            if id_to_label.get(pid, "") in _compiled_labels
        )
    else:
        # cargo tree unavailable or failed — fall back conservatively
        compiled_ids = frozenset(prod_reachable)

    # ── 2c. Compiled duplicate names (cargo tree --duplicates ground truth) ───
    # Packages that appear with genuinely different compiled versions on this
    # platform.  Same-version build-host/target splits are excluded.
    compiled_dup_names = _cargo_tree_compiled_duplicates()

    dev_reachable = set()
    for mid in workspace_members:
        for dr in node_deps.get(mid, {}).get("dev", set()):
            dev_reachable.add(dr)
            dev_reachable |= trans({dr}, "prod")

    build_reachable = set()
    for mid in workspace_members:
        for br in node_deps.get(mid, {}).get("build", set()):
            build_reachable.add(br)
            build_reachable |= trans({br}, "prod")

    # ── 3. Per-workspace-member stats ────────────────────────────────────────
    member_stats = []
    for mid in sorted(workspace_members, key=lambda i: packages[i]["name"]):
        pkg = packages[mid]
        direct = node_deps.get(mid, {"prod": set(), "dev": set(), "build": set()})

        def count_trans(roots):
            t = set()
            for dep_id in roots:
                t.add(dep_id)
                t |= trans({dep_id}, "prod")
            return t

        all_prod  = count_trans(direct["prod"])
        all_dev   = count_trans(direct["dev"])
        all_build = count_trans(direct["build"])

        optional_deps = {d["name"] for d in pkg.get("dependencies", []) if d.get("optional")}

        member_stats.append({
            "name":              pkg["name"],
            "version":           pkg["version"],
            "is_tooling":        mid in tooling_members,
            "direct_prod":       len(direct["prod"]),
            "direct_dev":        len(direct["dev"]),
            "direct_build":      len(direct["build"]),
            "trans_prod":        len(all_prod),
            "trans_dev":         len(all_dev),
            "trans_build":       len(all_build),
            "optional_dep_names": sorted(optional_deps),
            "prod_names":        sorted(id_to_label[i] for i in all_prod  if i in packages),
            "dev_names":         sorted(id_to_label[i] for i in all_dev   if i in packages),
            "build_names":       sorted(id_to_label[i] for i in all_build if i in packages),
        })

    # ── 4. Dev-only / duplicate / heaviness ──────────────────────────────────
    all_package_ids = set(packages.keys())
    non_workspace   = all_package_ids - workspace_members
    # Exclude tooling-reachable from dev_only: they are a separate category.
    dev_only        = non_workspace - prod_reachable - tooling_reachable

    name_versions = defaultdict(list)
    for p in packages.values():
        if p["id"] not in workspace_members:
            name_versions[p["name"]].append(p["version"])
    duplicates = {n: sorted(vs) for n, vs in name_versions.items() if len(vs) > 1}

    heaviness = []
    for pid in prod_reachable:
        if pid not in packages:
            continue
        t_raw      = trans({pid}, "prod")
        # Intersect with compiled_ids (cargo tree ground truth) so that phantom
        # packages — optional deps locked but not activated, or platform deps
        # for other targets — do not inflate the transitive dep count.
        # The difference (raw − compiled) is the "phantom" count.
        t_compiled = t_raw & compiled_ids
        heaviness.append((len(t_compiled), len(t_raw), id_to_label[pid]))
    heaviness.sort(reverse=True)

    return {
        "total_locked":        len(all_package_ids),
        "workspace_members":   len(workspace_members),
        "library_members":     len(library_members),
        "tooling_members":     len(tooling_members),
        "tooling_member_names": sorted(packages[mid]["name"] for mid in tooling_members),
        "prod_reachable":      len(prod_reachable),
        "tooling_reachable":   len(tooling_reachable),
        "dev_reachable":       len(dev_reachable),
        "build_reachable":     len(build_reachable),
        "dev_only_ids":        dev_only,
        "dev_only":            sorted(id_to_label[i] for i in dev_only if i in packages),
        "duplicates":         duplicates,
        "compiled_dup_names": compiled_dup_names,
        "heaviness":          heaviness,
        "compiled_ids":       compiled_ids,
        "member_stats":    member_stats,
        "id_to_label":     id_to_label,
        "packages":        packages,
        "node_deps":       node_deps,
    }


# ── dev-only source tracing ───────────────────────────────────────────────────

def compute_dev_sources(result: dict, meta: dict) -> dict:
    """
    For each direct dev-dependency of any workspace member, compute:
      - which workspace members list it as a direct dev-dep
      - which dev-only packages it transitively introduces

    Returns a dict keyed by the dep's label ("name vX.Y.Z"), each value:
      {
        "members":  sorted list of workspace member names,
        "packages": sorted list of dev-only package labels it introduces,
      }
    Only entries that introduce at least one dev-only package are included.
    """
    workspace_members = set(meta["workspace_members"])
    packages   = result["packages"]
    node_deps  = result["node_deps"]
    id_to_label = result["id_to_label"]
    dev_only_ids = result["dev_only_ids"]

    # dep_id → {members: set, packages: set}
    groups: dict = defaultdict(lambda: {"members": set(), "packages": set()})

    for mid in workspace_members:
        member_name = packages[mid]["name"]
        for dev_dep_id in node_deps.get(mid, {}).get("dev", set()):
            groups[dev_dep_id]["members"].add(member_name)
            reachable = _transitive(node_deps, {dev_dep_id}, "prod") | {dev_dep_id}
            for pid in reachable:
                if pid in dev_only_ids and pid in packages:
                    groups[dev_dep_id]["packages"].add(id_to_label[pid])

    out = {}
    for dep_id, info in groups.items():
        if not info["packages"]:
            continue
        dep_label = id_to_label.get(dep_id, dep_id)
        out[dep_label] = {
            "members":  sorted(info["members"]),
            "packages": sorted(info["packages"]),
        }
    return dict(sorted(out.items()))


# ── feature analysis ──────────────────────────────────────────────────────────

def analyse_features(meta: dict, result: dict) -> list:
    """
    For each workspace member, inspect the features requested for every direct
    production dependency and compare against:
      • what the dep's own default features are
      • what the resolved (workspace-unified) feature set is
    Returns a list of per-member dicts with per-dep findings.
    """
    packages = result["packages"]
    workspace_members = set(meta["workspace_members"])
    node_deps   = result["node_deps"]
    id_to_label = result["id_to_label"]

    # resolved_features: pkg_id → frozenset of enabled feature names
    resolved_features = {
        node["id"]: frozenset(f for f in node.get("features", []) if f != "default")
        for node in meta["resolve"]["nodes"]
    }

    # resolve_name_to_id: member_id → {dep_normalized_name: dep_pkg_id}
    resolve_name_to_id: dict = {
        node["id"]: {d["name"]: d["pkg"] for d in node.get("deps", [])}
        for node in meta["resolve"]["nodes"]
    }

    findings = []

    for mid in sorted(workspace_members, key=lambda i: packages[i]["name"]):
        pkg         = packages[mid]
        member_name = pkg["name"]
        rmap        = resolve_name_to_id.get(mid, {})
        dep_findings = []

        for dep in pkg.get("dependencies", []):
            if dep.get("kind") is not None:   # skip dev / build
                continue

            dep_name      = dep["name"]
            dep_name_norm = dep_name.replace("-", "_")
            dep_id        = rmap.get(dep_name_norm)

            if dep_id is None or dep_id not in packages:
                continue  # optional dep not activated in current build

            dep_pkg      = packages[dep_id]
            dep_feat_map = dep_pkg.get("features", {})
            dep_defaults = frozenset(dep_feat_map.get("default", []))

            explicit      = frozenset(dep.get("features", []))
            uses_defaults = dep.get("uses_default_features", True)
            optional      = dep.get("optional", False)

            resolved      = resolved_features.get(dep_id, frozenset())
            all_available = frozenset(k for k in dep_feat_map if k != "default")

            defaults_added = dep_defaults - explicit if uses_defaults else frozenset()

            this_crate_activated = expand_features(dep_feat_map, explicit)
            if uses_defaults:
                this_crate_activated |= expand_features(dep_feat_map, dep_defaults)

            # Also account for features this member activates on DEP via its own
            # [features] forwarding table, e.g. `std = ["sha2/std"]`.
            # Without this, such activations appear as spurious "+others".
            member_own_feats = resolved_features.get(mid, frozenset())
            member_feat_map  = pkg.get("features", {})
            dep_norm         = dep_name.replace("-", "_")
            self_forwarded: set = set()
            for mfeat in member_own_feats:
                for sub in member_feat_map.get(mfeat, []):
                    if "/" in sub and not sub.startswith("dep:"):
                        fwd_dep, fwd_feat = sub.split("/", 1)
                        if fwd_dep.replace("-", "_") == dep_norm:
                            self_forwarded.add(fwd_feat)
            if self_forwarded:
                this_crate_activated |= expand_features(dep_feat_map, self_forwarded)

            extra_from_others = resolved - this_crate_activated
            not_activated     = all_available - resolved

            issues = []
            if uses_defaults and dep_defaults:
                explicit_expanded = expand_features(dep_feat_map, explicit)
                if dep_defaults.issubset(explicit_expanded):
                    issues.append(
                        "default features are REDUNDANT: the explicit feature set already "
                        "covers all of them — add `default-features = false`"
                    )
                elif defaults_added and dep_id not in workspace_members and explicit:
                    # Two suppression rules above this point:
                    #  1. dep_id not in workspace_members — internal crates' defaults
                    #     are the feature API they were designed to present; change
                    #     the dep's own defaults, not the consumer's flag.
                    #  2. `and explicit` — if the consumer lists NO explicit features,
                    #     they are intentionally taking all defaults as their feature
                    #     set (e.g. `hickory-resolver = { workspace = true }` with
                    #     nothing added).  There is no accidental feature pull-in.
                    issues.append(
                        f"default features add: [{', '.join(sorted(defaults_added))}] "
                        "— consider `default-features = false` if these are unneeded"
                    )

            if extra_from_others:
                issues.append(
                    f"other workspace members activate extra features: "
                    f"[{', '.join(sorted(extra_from_others))}]"
                )

            # ── no-op detection ───────────────────────────────────────────
            # If defaults_added features are already mandated by non-workspace
            # transitive deps (e.g. reqwest→cookie_store→idna compiled_data),
            # setting default-features=false on this workspace member's dep
            # declaration would not change the compiled binary at all.
            # Replace the ⚠ warning with an informational ℹ note in that case.
            # Only runs when the warning itself was eligible (same guards as above).
            noop_activators: dict = {}
            if defaults_added and uses_defaults \
                    and dep_id not in workspace_members and explicit:
                noop_activators = find_transitive_activators(
                    dep_id, dep_pkg, frozenset(defaults_added),
                    workspace_members, node_deps, packages, id_to_label,
                )
                covered = frozenset(
                    f for feats in noop_activators.values() for f in feats
                )
                if covered >= frozenset(defaults_added):
                    # All flagged defaults are still mandated by other sources.
                    issues = [
                        i for i in issues if "default features add" not in i
                    ]
                    by_str = ", ".join(sorted(noop_activators))
                    issues.append(
                        f"default features add: "
                        f"[{', '.join(sorted(defaults_added))}] "
                        f"— no-op: already mandated by transitive dep(s): {by_str}"
                    )

            dep_findings.append({
                "name":             dep_name,
                "version":          dep_pkg["version"],
                "optional":         optional,
                "explicit":         sorted(explicit),
                "uses_defaults":    uses_defaults,
                "dep_defaults":     sorted(dep_defaults),
                "defaults_added":   sorted(defaults_added),
                "resolved":         sorted(resolved),
                "extra_from_others": sorted(extra_from_others),
                "not_activated":    sorted(not_activated),
                "noop_activators":  noop_activators,
                "issues":           issues,
            })

        findings.append({"member": member_name, "deps": dep_findings})

    return findings


def cross_crate_feature_table(feature_findings: list) -> list:
    """
    Find packages that multiple workspace members depend on directly and show
    the union of their feature requests.
    """
    shared: dict = defaultdict(dict)
    for mf in feature_findings:
        for dep in mf["deps"]:
            key = f"{dep['name']} v{dep['version']}"
            shared[key][mf["member"]] = {
                "explicit":      dep["explicit"],
                "uses_defaults": dep["uses_defaults"],
                "defaults_added": dep["defaults_added"],
            }

    return [
        {"package": pkg, "requesters": requesters}
        for pkg, requesters in sorted(shared.items())
        if len(requesters) > 1
    ]


# ── derived suggestions ───────────────────────────────────────────────────────

def build_feature_suggestions(feature_findings: list) -> dict:
    """
    Aggregate feature issues across all workspace members.

    Returns:
      redundant     — safe: explicit features already cover all defaults
      defaults_add  — consider: defaults activate features beyond explicit list
      extra_others  — informational: other workspace members activate extra features
    """
    redundant: dict         = defaultdict(list)   # (dep, ver) → [members]
    defaults_add: dict      = {}                  # (dep, ver) → {members, added, explicit}
    defaults_add_noop: dict = {}                  # same shape; no-op: already covered
    extra_others: dict      = {}                  # (dep, ver) → {members, extra}

    for mf in feature_findings:
        for dep in mf["deps"]:
            key = (dep["name"], dep["version"])
            for issue in dep["issues"]:
                if "REDUNDANT" in issue:
                    redundant[key].append(mf["member"])
                elif "default features add" in issue:
                    is_noop = "no-op" in issue
                    bucket  = defaults_add_noop if is_noop else defaults_add
                    if key not in bucket:
                        bucket[key] = {
                            "members":         [],
                            "added":           dep["defaults_added"],
                            "explicit":        dep["explicit"],
                            "noop_activators": dep.get("noop_activators", {}),
                        }
                    bucket[key]["members"].append(mf["member"])
                if "other workspace members" in issue:
                    if key not in extra_others:
                        extra_others[key] = {"members": [], "extra": dep["extra_from_others"]}
                    extra_others[key]["members"].append(mf["member"])

    return {
        "redundant":         dict(redundant),
        "defaults_add":      defaults_add,
        "defaults_add_noop": defaults_add_noop,
        "extra_others":      extra_others,
    }


# ── who pulls in a package ────────────────────────────────────────────────────

def who_requires(target_id: str, result: dict) -> list:
    refs = []
    for pid, deps in result["node_deps"].items():
        for kind in ("prod", "dev", "build"):
            if target_id in deps[kind]:
                label = result["id_to_label"].get(pid, pid)
                refs.append(f"{label} [{kind}]")
    return refs


# ── reverse-path tracing (for --why and --trace-feature) ─────────────────────

def build_reverse_dep_map(result: dict) -> dict:
    """
    Reverse dependency map: dep_id → list of (parent_id, dep_kind).
    dep_kind is how parent depends on dep: 'prod', 'dev', or 'build'.
    """
    rev: dict = defaultdict(list)
    for nid, deps in result["node_deps"].items():
        for kind in ("prod", "dev", "build"):
            for dep_id in deps[kind]:
                rev[dep_id].append((nid, kind))
    return dict(rev)


def paths_to_workspace(start_id: str, rev_deps: dict, workspace_members: set,
                       id_to_label: dict, max_paths: int = 20) -> list:
    """
    BFS through reverse dependency edges from start_id to any workspace member.

    Returns a list of paths.  Each path is a list of (label, edge_kind) tuples.
    edge_kind is None for the first entry; for subsequent entries it describes
    how the package at that position depends on the previous one:

        A →[edge_kind]→ B  means  B depends on A with dep-kind edge_kind.

    So plain '→' is a production dep, '→[dev]→' a dev dep, etc.
    """
    if start_id in workspace_members:
        return [[(id_to_label.get(start_id, start_id), None)]]

    visited: set = set()
    results: list = []
    queue: deque = deque(
        [(start_id, [(id_to_label.get(start_id, start_id), None)])]
    )

    while queue and len(results) < max_paths:
        cur_id, path = queue.popleft()
        if cur_id in workspace_members:
            results.append(path)
            continue
        if cur_id in visited:
            continue
        visited.add(cur_id)
        for parent_id, kind in sorted(rev_deps.get(cur_id, []),
                                      key=lambda x: id_to_label.get(x[0], "")):
            parent_label = id_to_label.get(parent_id, parent_id)
            queue.append((parent_id, path + [(parent_label, kind)]))

    return results


def format_path(path: list) -> str:
    """
    Format a [(label, edge_kind), ...] path into a readable string.
    Production edges (the common case) are shown as plain '→'.
    Dev and build edges are annotated: '→[dev]→', '→[build]→'.
    """
    result = path[0][0]
    for label, kind in path[1:]:
        sep = " → " if kind == "prod" else f" →[{kind}]→ "
        result += sep + label
    return result


def find_feature_enablers(dep_name: str, feature: str, meta: dict) -> list:
    """
    Find all packages in the lock file that explicitly list FEATURE in their
    dependency declaration on DEP_NAME.

    Returns a sorted list of dicts: {id, label, features_requested}.
    """
    dep_norm = dep_name.replace("-", "_")
    seen: set = set()
    results: list = []

    for pkg in meta["packages"]:
        for dep in pkg.get("dependencies", []):
            if dep["name"].replace("-", "_") != dep_norm:
                continue
            if feature not in dep.get("features", []):
                continue
            if pkg["id"] in seen:
                continue
            seen.add(pkg["id"])
            results.append({
                "id":                 pkg["id"],
                "label":              f"{pkg['name']} v{pkg['version']}",
                "features_requested": sorted(dep.get("features", [])),
            })

    return sorted(results, key=lambda e: e["label"])


def print_trace_feature(dep_name: str, feature: str,
                        meta: dict, result: dict) -> None:
    """
    For --trace-feature DEP FEATURE.

    1. Find every package that explicitly requests FEATURE from DEP_NAME.
    2. Trace each one back to workspace members and show whether the path
       goes through production or dev/build edges.
    """
    workspace_members = set(meta["workspace_members"])
    id_to_label       = result["id_to_label"]
    rev_deps          = build_reverse_dep_map(result)

    enablers = find_feature_enablers(dep_name, feature, meta)

    if not enablers:
        print(f"\nNo package explicitly requests '{feature}' from '{dep_name}'.")
        # Helpful hint: check if the feature is in the dep's own defaults.
        for pkg in meta["packages"]:
            if pkg["name"].replace("-", "_") == dep_name.replace("-", "_"):
                feat_map = pkg.get("features", {})
                if feature in feat_map.get("default", []):
                    print(f"  Note: '{feature}' is in {pkg['name']}'s default "
                          "features — every dep that uses defaults activates it.")
        return

    print(f"\nPackages that explicitly request '{feature}' from {dep_name}:\n")
    for en in enablers:
        print(f"  {en['label']}  (requests: {', '.join(en['features_requested'])})")
        paths = paths_to_workspace(en["id"], rev_deps, workspace_members,
                                   id_to_label)
        if not paths:
            print("    (not reachable from any workspace member)")
        else:
            for path in paths:
                print(f"    • {format_path(path)}")
        print()


def print_why(name: str, meta: dict, result: dict) -> None:
    """
    For --why NAME.

    Show all paths from the named package back to workspace members with
    dep-kind annotations on each hop.  Equivalent to `cargo tree --invert`
    but distinguishing production, dev, and build edges.
    """
    workspace_members = set(meta["workspace_members"])
    id_to_label       = result["id_to_label"]
    rev_deps          = build_reverse_dep_map(result)

    name_norm = name.lower().replace("-", "_")
    matches = [
        (pid, label)
        for pid, label in sorted(id_to_label.items(), key=lambda x: x[1])
        if name_norm in label.lower().replace("-", "_")
    ]

    if not matches:
        print(f"No package matching '{name}' found in lock file.")
        return

    for pkg_id, label in matches:
        if pkg_id in workspace_members:
            print(f"\n{label} — is a workspace member")
            continue
        print(f"\n{label}")
        paths = paths_to_workspace(pkg_id, rev_deps, workspace_members,
                                   id_to_label)
        if not paths:
            print("  (no path found to any workspace member)")
        else:
            for path in paths:
                print(f"  • {format_path(path)}")


# ── well-known package notes (workspace-independent) ─────────────────────────
#
# These describe commonly-encountered external packages.  No workspace-specific
# crate names appear here; everything workspace-specific is derived from the
# analysis at runtime.

KNOWN_NOTES = {
    "proptest":       "property-based test framework; heavy chain (bit-vec, bit-set, rusty-fork, rand)",
    "criterion":      "benchmark harness; brings ciborium, half, anes, plotters, oorandom (~30 crates)",
    "bindgen":        "C binding generator; pulls clang-sys, libloading, regex chain",
    "rand":           "random number generation; consider fastrand (zero deps) for simpler use cases",
    "clap":           "CLI arg parser; default features include color/suggestions — consider trimming for minimal binaries",
    "serde_json":     "JSON serialization; unlikely needed in no-std or pure-library crates",
    "num-bigint":     "arbitrary-precision integers",
    "once_cell":      "lazy initialisation; Rust std OnceLock / LazyLock available since 1.70",
    "lazy_static":    "global lazy init macro; prefer std OnceLock / LazyLock (Rust 1.70+)",
    "bit-vec":        "bit vector data structure",
    "bit-set":        "bit set built on bit-vec",
    "ciborium":       "CBOR serialization (typically a criterion dependency)",
    "plotters":       "plotting library (typically a criterion dependency)",
    "half":           "f16 / f128 floating-point (typically a criterion dependency)",
    "oorandom":       "small non-cryptographic RNG (typically a criterion dependency)",
    "rusty-fork":     "process isolation for property tests (proptest dependency)",
    "wait-timeout":   "process wait with timeout (rusty-fork / proptest dependency)",
    "trybuild":       "compile-error test framework for proc-macro crates",
    "dissimilar":     "diff algorithm (trybuild dependency)",
    "prettyplease":   "Rust code formatter (trybuild dependency)",
    "tempfile":       "temporary file/dir management",
    "walkdir":        "recursive directory traversal",
    "rayon":          "data-parallelism library",
    "regex":          "regular expressions; can be heavy (aho-corasick, memchr)",
}


# ── print helpers ─────────────────────────────────────────────────────────────

def _known_note(label: str) -> str:
    for pattern, msg in KNOWN_NOTES.items():
        if pattern in label:
            return f"  ← {msg}"
    return ""


def _fmt_list(items: list, limit: int = 8) -> str:
    if not items:
        return "(none)"
    shown  = items[:limit]
    suffix = f", …+{len(items)-limit}" if len(items) > limit else ""
    return "[" + ", ".join(shown) + suffix + "]"


def _members_str(members: list) -> str:
    return ", ".join(sorted(members))


# ── Fedora packaging coverage ─────────────────────────────────────────────────

def query_fedora_crates(repo: str = "rawhide") -> dict:
    """
    Query a DNF repository for packaged Rust crate devel packages.

    Returns {normalised_crate_name: sorted_list_of_versions}, where names are
    normalised to hyphens.  Returns {} if dnf is unavailable or the query fails.
    Feature-variant packages (those containing '+' in the package name) are
    excluded — only the base ``rust-<crate>-devel`` packages are counted.
    """
    print(f"Querying Fedora repo '{repo}' for packaged Rust crates…",
          file=sys.stderr)
    try:
        r = subprocess.run(
            ["dnf", "repoquery", "--quiet", f"--repo={repo}", "rust-*-devel"],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        print("  dnf not found — skipping Fedora coverage check.", file=sys.stderr)
        return {}
    except subprocess.TimeoutExpired:
        print("  dnf repoquery timed out — skipping Fedora coverage check.",
              file=sys.stderr)
        return {}

    if r.returncode != 0:
        print(f"  dnf repoquery failed (exit {r.returncode}) — skipping.",
              file=sys.stderr)
        return {}

    crates: dict = defaultdict(set)
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or "+" in line:          # skip feature-variant packages
            continue
        # NEVRA format: rust-<crate>-devel-<epoch>:<version>-<release>.<arch>
        no_arch    = line.rsplit(".", 1)[0]  # strip trailing .arch
        no_release = no_arch.rsplit("-", 1)[0]  # strip -<release>
        parts = no_release.rsplit("-", 1)    # split pkg_name from epoch:version
        if len(parts) != 2:
            continue
        pkg_name, evr = parts
        if not pkg_name.startswith("rust-") or not pkg_name.endswith("-devel"):
            continue
        crate_raw = pkg_name[len("rust-"):-len("-devel")]
        version   = evr.split(":", 1)[-1]   # strip epoch
        crates[crate_raw.replace("_", "-")].add(version)

    return {name: sorted(vers) for name, vers in crates.items()}


def _parse_version(v: str) -> tuple:
    """Parse 'X.Y.Z' into (int, int, int), ignoring pre-release/build metadata."""
    v = v.split("-")[0].split("+")[0]
    parts = v.split(".")
    nums = []
    for p in parts[:3]:
        try:
            nums.append(int(p))
        except ValueError:
            nums.append(0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


def _req_satisfied(req: str, version: str) -> bool:
    """
    Return True if ``version`` satisfies the Cargo requirement string ``req``.

    Handles standard Cargo requirement syntax:
      ^X.Y.Z   caret (default when no operator is given)
      ~X.Y.Z   tilde
      =X.Y.Z   exact
      >=, <=, >, <   comparison operators
      *        wildcard (any version)
      req1, req2   AND of multiple clauses
    """
    ver = _parse_version(version)
    for clause in req.split(","):
        clause = clause.strip()
        if not clause or clause == "*":
            continue
        if clause.startswith("^"):
            spec  = _parse_version(clause[1:])
            parts = clause[1:].split(".")
            if spec[0] > 0:
                ok = ver[0] == spec[0] and ver >= spec
            elif len(parts) > 1 and spec[1] > 0:
                ok = ver[0] == 0 and ver[1] == spec[1] and ver >= spec
            else:
                ok = ver == spec
            if not ok:
                return False
        elif clause.startswith("~"):
            spec  = _parse_version(clause[1:])
            parts = clause[1:].split(".")
            if len(parts) >= 3:
                ok = ver[0] == spec[0] and ver[1] == spec[1] and ver >= spec
            elif len(parts) == 2:
                ok = ver[0] == spec[0] and ver[1] == spec[1]
            else:
                ok = ver[0] == spec[0]
            if not ok:
                return False
        elif clause.startswith(">="):
            if not (ver >= _parse_version(clause[2:])):
                return False
        elif clause.startswith("<="):
            if not (ver <= _parse_version(clause[2:])):
                return False
        elif clause.startswith(">"):
            if not (ver > _parse_version(clause[1:])):
                return False
        elif clause.startswith("<"):
            if not (ver < _parse_version(clause[1:])):
                return False
        elif clause.startswith("="):
            if ver != _parse_version(clause[1:]):
                return False
        else:
            # Bare version — Cargo treats as caret
            spec  = _parse_version(clause)
            parts = clause.split(".")
            if spec[0] > 0:
                ok = ver[0] == spec[0] and ver >= spec
            elif len(parts) > 1 and spec[1] > 0:
                ok = ver[0] == 0 and ver[1] == spec[1] and ver >= spec
            else:
                ok = ver == spec
            if not ok:
                return False
    return True


def _find_dep_requirements(dep_id: str, dep_name: str, result: dict) -> list:
    """
    Return [(parent_label, req_str), ...] for every package that directly
    depends on dep_id via a production edge, from their Cargo.toml declarations.
    """
    packages    = result["packages"]
    node_deps   = result["node_deps"]
    id_to_label = result["id_to_label"]
    dep_norm    = dep_name.replace("-", "_")

    reqs = []
    for pid, deps in node_deps.items():
        if dep_id not in deps.get("prod", set()):
            continue
        pkg = packages.get(pid)
        if not pkg:
            continue
        for dep_decl in pkg.get("dependencies", []):
            if dep_decl["name"].replace("-", "_") == dep_norm:
                reqs.append((id_to_label.get(pid, pid), dep_decl.get("req", "*")))
    return reqs


def analyse_fedora_coverage(result: dict, meta: dict, fedora_crates: dict) -> dict:
    """
    Cross-reference compiled production deps against Fedora packaged crates.

    Returns a dict with three keys:
      missing       {label → our_version}
                    crate not packaged in Fedora at all
      version_only  {label → {"our_ver", "fedora_vers", "alignable", "reqs"}}
                    name present in Fedora but our version is absent;
                    "alignable" lists Fedora versions that satisfy all requirements,
                    "reqs" is [(parent_label, req_str), ...] from direct dependents
      present       {label → our_version}
                    exact version available in Fedora
    """
    workspace_members = set(meta["workspace_members"])
    packages = result["packages"]
    # compiled_ids is already the production-reachable set filtered to packages
    # actually compiled on this platform (cargo tree ground truth).
    compiled = result.get("compiled_ids", frozenset())

    missing: dict      = {}
    version_only: dict = {}
    present: dict      = {}

    for pid in sorted(compiled,
                      key=lambda p: result["id_to_label"].get(p, "")):
        if pid in workspace_members:
            continue
        pkg = packages.get(pid)
        if not pkg:
            continue
        name    = pkg["name"]
        version = pkg["version"]
        norm    = name.replace("_", "-")
        label   = f"{name} v{version}"

        if norm not in fedora_crates:
            missing[label] = version
        elif version in fedora_crates[norm]:
            present[label] = version
        else:
            fedora_vers = fedora_crates[norm]
            reqs        = _find_dep_requirements(pid, name, result)
            alignable   = [
                fv for fv in fedora_vers
                if all(_req_satisfied(req, fv) for _, req in reqs)
            ]
            version_only[label] = {
                "our_ver":     version,
                "fedora_vers": fedora_vers,
                "alignable":   alignable,
                "reqs":        reqs,
            }

    return {"missing": missing, "version_only": version_only, "present": present}


def print_fedora_section(coverage: dict, repo: str) -> None:
    missing      = coverage["missing"]
    version_only = coverage["version_only"]
    present      = coverage["present"]
    total = len(missing) + len(version_only) + len(present)

    print(f"\n── H. Fedora packaging coverage (repo: {repo}) ──────────────────────")
    print(f"   {len(present)}/{total} compiled production deps present in Fedora "
          f"at the exact required version.")
    print()

    if missing:
        print(f"   Not packaged in Fedora — must be declared bundled ({len(missing)}):")
        for label in sorted(missing):
            print(f"     • {label}")
        print()

    if version_only:
        can_align    = {k: v for k, v in version_only.items() if v["alignable"]}
        cannot_align = {k: v for k, v in version_only.items() if not v["alignable"]}

        print(f"   In Fedora but at a different version ({len(version_only)}):")
        for label, info in sorted(version_only.items()):
            fedora_str = ", ".join(info["fedora_vers"])
            print(f"     • {label}  (Fedora has: {fedora_str})")
            unique_reqs = sorted({req for _, req in info["reqs"]})
            reqs_str    = ", ".join(unique_reqs) if unique_reqs else "*"
            if info["alignable"]:
                align_str = ", ".join(info["alignable"])
                print(f"       ✓ can align to {align_str}  [req: {reqs_str}]")
            else:
                print(f"       ✗ cannot align — Fedora versions incompatible  "
                      f"[req: {reqs_str}]")
        print()

        if can_align:
            print(f"   {len(can_align)} crate(s) can be aligned to a Fedora version "
                  f"(update Cargo.lock via `cargo update -p <crate> --precise <ver>`):")
            for label, info in sorted(can_align.items()):
                print(f"     cargo update -p {label.split(' v')[0]} "
                      f"--precise {info['alignable'][-1]}")
            print()

        need_bundled = {**{k: v["our_ver"] for k, v in cannot_align.items()},
                        **{k: v["our_ver"] for k, v in can_align.items()}}
    else:
        need_bundled = {}

    all_bundled = {**{k: v for k, v in missing.items()}, **need_bundled}
    if all_bundled:
        print("   Suggested Provides: lines for the RPM spec:")
        for label, ver in sorted(all_bundled.items()):
            name = label.split(" v")[0]
            print(f"     Provides: bundled(crate({name})) = {ver}")
        print()
    else:
        print("   All compiled production deps are available in Fedora at the "
              "required version — no bundled declarations needed for external crates.")


# ── feature report (section F + G) ───────────────────────────────────────────

def print_feature_report(feature_findings: list, cross_table: list, verbose: bool) -> None:
    print("\n" + "=" * 70)
    print("FEATURE USAGE ANALYSIS")
    print("=" * 70)

    print("\n── F. Per-member direct production dependency features ───────────────")
    print("   Legend:")
    print("     explicit  = features listed in Cargo.toml")
    print("     defaults  = dep's own `[features] default = [...]`")
    print("     resolved  = features actually compiled (workspace-wide union)")
    print("     +others   = extra features enabled by other workspace members")
    print("     unused    = features available in dep but not activated anywhere")
    print()

    any_issues = False
    for mf in feature_findings:
        has_issues = any(d["issues"] for d in mf["deps"])
        if not has_issues and not verbose:
            continue
        print(f"  ┌─ {mf['member']} ───")
        for dep in mf["deps"]:
            if not dep["issues"] and not verbose:
                continue
            opt_tag = " (optional)" if dep["optional"] else ""
            print(f"  │  {dep['name']} v{dep['version']}{opt_tag}")
            expl_str = _fmt_list(dep["explicit"]) if dep["explicit"] else "(none)"
            print(f"  │    explicit  : {expl_str}")
            dtag = "ON" if dep["uses_defaults"] else "OFF"
            print(f"  │    defaults  : {dtag} → {_fmt_list(dep['dep_defaults'])}")
            if dep["defaults_added"] and dep["uses_defaults"]:
                print(f"  │    +defaults : {_fmt_list(dep['defaults_added'])}")
            print(f"  │    resolved  : {_fmt_list(dep['resolved'])}")
            if dep["extra_from_others"]:
                print(f"  │    +others   : {_fmt_list(dep['extra_from_others'])}")
            if verbose and dep["not_activated"]:
                print(f"  │    unused    : {_fmt_list(dep['not_activated'])}")
            for issue in dep["issues"]:
                marker = "ℹ " if "no-op" in issue else "⚠ "
                print(f"  │    {marker} {issue}")
            print("  │")
            any_issues = True
        print("  └─")
        print()

    if not any_issues and not verbose:
        print("  No issues found (pass --verbose to show all deps).")

    print("\n── G. Cross-crate feature unification ───────────────────────────────")
    print("   Packages depended on by multiple workspace members directly.")
    print("   Cargo unifies all their feature requests into one compiled version.")
    print()

    for entry in cross_table:
        pkg       = entry["package"]
        requesters = entry["requesters"]
        all_explicit = set()
        all_defaults = set()
        for req_info in requesters.values():
            all_explicit.update(req_info["explicit"])
            if req_info["uses_defaults"]:
                all_defaults.update(req_info["defaults_added"])
        print(f"  {pkg}")
        for member, req_info in sorted(requesters.items()):
            ud   = "defaults=ON" if req_info["uses_defaults"] else "defaults=OFF"
            expl = _fmt_list(req_info["explicit"]) if req_info["explicit"] else "(none)"
            print(f"    • {member:<24} explicit={expl:<30} {ud}")
            if req_info["defaults_added"]:
                print(f"      +defaults: {_fmt_list(req_info['defaults_added'])}")
        if len(all_explicit) > 1 or all_defaults:
            union_note = sorted(all_explicit | all_defaults)
            print(f"    → unified features: {_fmt_list(union_note)}")
        print()


# ── suggestions (sections A–E) ────────────────────────────────────────────────

def print_suggestions(result: dict, dev_sources: dict, feat_sugg: dict) -> None:
    print("\n" + "=" * 70)
    print("ACTIONABLE SUGGESTIONS")
    print("=" * 70)

    packages    = result["packages"]
    id_to_label = result["id_to_label"]

    # ── A. Dev-only packages, grouped by introducing dev-dep ─────────────────
    print("\n── A. Dev/test/bench-only packages (never shipped) ─────────────────")
    print("   Grouped by the direct dev-dependency that introduces them.")
    print("   To remove a group, remove that dev-dep from the workspace member.\n")

    for dep_label, info in dev_sources.items():
        members_str = ", ".join(info["members"])
        print(f"  {dep_label}  [dev-dep of: {members_str}]")
        for pkg_label in info["packages"]:
            print(f"    • {pkg_label}{_known_note(pkg_label)}")
        print()

    # Show any dev-only packages not traced to a source (e.g. orphans)
    traced = {lbl for info in dev_sources.values() for lbl in info["packages"]}
    untraced = sorted(set(result["dev_only"]) - traced)
    if untraced:
        print("  (other dev/build-only packages not traced to a single dev-dep)")
        for label in untraced:
            print(f"    • {label}{_known_note(label)}")
        print()

    # ── B. Duplicate versions ─────────────────────────────────────────────────
    print("── B. Duplicate package versions ────────────────────────────────────")
    print("   [compiled] = different versions actually built on this platform")
    print("   [phantom]  = in Cargo.lock but not compiled (unactivated optional")
    print("                features or platform-conditional deps for other targets)")
    print()
    compiled_dups = result.get("compiled_dup_names", set())
    if result["duplicates"]:
        has_compiled = False
        for name, versions in sorted(result["duplicates"].items()):
            if name in compiled_dups:
                tag = "  [compiled]"
                has_compiled = True
            else:
                tag = "  [phantom]"
            print(f"   • {name}: {', '.join(versions)}{tag}")
        print()
        if has_compiled:
            print("   → For [compiled] duplicates: `cargo tree --invert <name>@<ver>`")
            print("     to trace; unify with [patch.crates-io] or update transitive deps.")
        else:
            print("   All duplicates are phantom — no action needed.")
    else:
        print("   None found – good!")

    # ── C. Feature reduction opportunities (fully derived from analysis) ──────
    print("\n── C. Feature reduction opportunities ───────────────────────────────")

    # C1 – safe: defaults are fully covered by explicit features
    redundant = feat_sugg["redundant"]
    if redundant:
        print("  Safe: add `default-features = false`")
        print("  (explicit features already cover the dep's entire default set)\n")
        for (dep, ver), members in sorted(redundant.items()):
            print(f"   • {_members_str(members)} → {dep} v{ver}")
        print()

    # C2 – consider: defaults add features beyond the explicit list
    defaults_add = feat_sugg["defaults_add"]
    if defaults_add:
        print("  Consider: defaults add features not in the explicit list.")
        print("  Verify each before disabling — the extra features may be needed.\n")
        for (dep, ver), info in sorted(defaults_add.items()):
            members_str  = _members_str(info["members"])
            explicit_str = _fmt_list(info["explicit"]) if info["explicit"] else "(none)"
            added_str    = _fmt_list(info["added"])
            print(f"   • {members_str} → {dep} v{ver}")
            print(f"     explicit={explicit_str}  defaults add={added_str}")
        print()

    # C2b – no-op: defaults add features but they are already mandated by
    #        non-workspace transitive deps; setting default-features=false here
    #        would not change the compiled binary at all.
    defaults_add_noop = feat_sugg["defaults_add_noop"]
    if defaults_add_noop:
        print("  No-op (informational): defaults add features that are already")
        print("  mandated by non-workspace transitive deps — setting")
        print("  `default-features = false` here would not change the binary.\n")
        for (dep, ver), info in sorted(defaults_add_noop.items()):
            members_str  = _members_str(info["members"])
            explicit_str = _fmt_list(info["explicit"]) if info["explicit"] else "(none)"
            added_str    = _fmt_list(info["added"])
            print(f"   • {members_str} → {dep} v{ver}")
            print(f"     explicit={explicit_str}  defaults add={added_str}")
            if info["noop_activators"]:
                by_str = ", ".join(sorted(info["noop_activators"]))
                print(f"     already activated by: {by_str}")
        print()

    # C3 – informational: features activated by other workspace members
    extra_others = feat_sugg["extra_others"]
    if extra_others:
        print("  Informational: features activated by other workspace members.")
        print("  These are resolved at workspace level and need no action per-crate.\n")
        for (dep, ver), info in sorted(extra_others.items()):
            members_str = _members_str(info["members"])
            extra_str   = _fmt_list(info["extra"])
            print(f"   • {members_str} → {dep} v{ver}  +others={extra_str}")
        print()

    if not redundant and not defaults_add and not defaults_add_noop and not extra_others:
        print("  No feature reduction opportunities found.")

    # ── D. Production dep footprint per workspace member ─────────────────────
    print("── D. Production dep footprint per workspace member ─────────────────")
    print("   Sorted by transitive production dependency count.\n")

    sorted_stats = sorted(result["member_stats"], key=lambda ms: (ms["is_tooling"], ms["trans_prod"], ms["name"]))
    name_w = max((len(ms["name"]) for ms in sorted_stats), default=0)
    for ms in sorted_stats:
        d = ms["direct_prod"]
        t = ms["trans_prod"]
        note = ""
        if ms["is_tooling"]:
            note = "  [tooling, publish=false]"
        elif t == 0 and d == 0:
            note = "  (no external production deps)"
        elif ms["direct_dev"] > 0 and t == 0:
            note = "  (all deps are dev/optional)"
        print(f"   {ms['name']:<{name_w}}  {d:>2} direct  {t:>3} transitive{note}")
    print()

    # Find the lightest library member (non-zero prod deps, not a tooling crate)
    lib_stats = [ms for ms in sorted_stats if ms["trans_prod"] > 0 and not ms["is_tooling"]]
    if lib_stats:
        lightest = lib_stats[0]
        print(f"   Smallest production footprint: {lightest['name']} "
              f"({lightest['trans_prod']} transitive prod deps)")

    # ── E. Heaviest production deps by transitive closure ────────────────────
    compiled_labels = {
        result["id_to_label"].get(pid, "") for pid in result.get("compiled_ids", set())
    }
    print("\n── E. Heaviest production deps (by transitive closure size) ─────────")
    print("   'transitive' = deps reachable from this pkg in the compiled prod graph.")
    print("   '+phantom'   = additional packages in the resolve graph but NOT compiled")
    print("                  (unactivated optional deps or other-platform conditionals).")
    print()
    for filtered_count, raw_count, label in result["heaviness"][:12]:
        phantom = raw_count - filtered_count
        phantom_note = f"  (+{phantom} phantom)" if phantom else ""
        print(f"   {filtered_count:>3} transitive  {label}{phantom_note}")
    print()

    # Dead-end detection:
    #   Type A — package itself is not compiled (it's fully phantom):
    #            appears in cargo metadata's resolve graph but not in cargo tree.
    #   Type B — package is compiled but its resolve-graph transitive closure is
    #            inflated by phantom deps (ratio phantom/raw ≥ 20 %).
    #
    # We only report packages with a meaningful phantom count (≥ 5) to avoid
    # noise from minor platform-conditional differences.
    type_a = [
        (fc, rc, lbl)
        for fc, rc, lbl in result["heaviness"]
        if lbl not in compiled_labels and rc - fc >= 5
    ]
    type_b = [
        (fc, rc, lbl)
        for fc, rc, lbl in result["heaviness"]
        if lbl in compiled_labels and rc - fc >= 5 and (rc - fc) / rc >= 0.20
    ]
    if type_a:
        print("   ── E1. Phantom packages (in resolve graph but not compiled on this platform)")
        print("         These may be unactivated optional features or other-target deps.")
        for fc, rc, lbl in type_a:
            phantom = rc - fc
            print(f"     • {lbl}: {phantom} phantom deps"
                  f"  (run --why {lbl.split()[0]} to trace)")
        print()
    if type_b:
        print("   ── E2. Compiled packages with ≥20 % phantom transitive deps")
        print("         Their resolve-graph footprint is significantly inflated.")
        for fc, rc, lbl in type_b:
            phantom = rc - fc
            pct = 100 * phantom // rc
            print(f"     • {lbl}: {fc} compiled + {phantom} phantom ({pct}%) = {rc} total")
        print()


# ── top-level report ──────────────────────────────────────────────────────────

def print_report(result: dict, feature_findings: list, cross_table: list,
                 dev_sources: dict, feat_sugg: dict, meta: dict,
                 verbose: bool, fedora_coverage=None, fedora_repo="rawhide") -> None:
    wname = workspace_name(meta)
    print("=" * 70)
    print(f"DEPENDENCY ANALYSIS — {wname}")
    print("=" * 70)
    print(f"\nWorkspace root               : {meta.get('workspace_root', '(unknown)')}")
    print(f"Total packages in Cargo.lock : {result['total_locked']}")
    print(f"Workspace members            : {result['workspace_members']}")
    print(f"  Library crates             : {result['library_members']}")
    if result["tooling_members"]:
        names = ", ".join(result["tooling_member_names"])
        print(f"  Tooling crates (publish=false): {result['tooling_members']}  [{names}]")
    print(f"Production-reachable pkgs    : {result['prod_reachable']}")
    print(f"  (reachable via library crates' non-dev, non-build edges)")
    if result["tooling_reachable"]:
        print(f"Tooling-only pkgs            : {result['tooling_reachable']}")
        print(f"  (prod deps of tooling crates, not part of any shipped library)")
    print(f"Dev/test-only pkgs           : {len(result['dev_only'])}")
    print(f"  (never compiled into any shipped artifact)")
    print(f"Duplicate package versions   : {len(result['duplicates'])}")

    print("\n── Per-workspace-member summary ─────────────────────────────────────")
    header = (
        f"{'Crate':<24} {'Prod(D)':>7} {'Prod(T)':>7} "
        f"{'Dev(D)':>6} {'Dev(T)':>6} {'Bld(D)':>6}"
    )
    print(header)
    print("-" * len(header))
    for ms in result["member_stats"]:
        print(
            f"{ms['name']:<24} "
            f"{ms['direct_prod']:>7} "
            f"{ms['trans_prod']:>7} "
            f"{ms['direct_dev']:>6} "
            f"{ms['trans_dev']:>6} "
            f"{ms['direct_build']:>6}"
        )
    print()
    print("  Prod(D)/Dev(D)/Bld(D) = direct deps by kind")
    print("  Prod(T)/Dev(T)        = transitive count (following prod edges)")

    print("\n── Optional deps per crate (inactive in default build) ──────────────")
    any_optional = False
    for ms in result["member_stats"]:
        if ms["optional_dep_names"]:
            print(f"  {ms['name']}: {', '.join(ms['optional_dep_names'])}")
            any_optional = True
    if not any_optional:
        print("  (none)")

    print_feature_report(feature_findings, cross_table, verbose)
    print_suggestions(result, dev_sources, feat_sugg)
    if fedora_coverage is not None:
        print_fedora_section(fedora_coverage, fedora_repo)


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyse a Cargo workspace's dependencies and propose reductions"
    )
    parser.add_argument("--json",    action="store_true",
                        help="Output raw analysis as JSON")
    parser.add_argument("--verbose", action="store_true",
                        help="Show all deps in feature section, not just issues")
    parser.add_argument("--who-needs", metavar="NAME",
                        help="Show which packages directly depend on NAME")
    parser.add_argument("--why", metavar="NAME",
                        help="Trace NAME back to workspace members via all paths "
                             "(like `cargo tree --invert`, with prod/dev/build labels)")
    parser.add_argument("--trace-feature", nargs=2, metavar=("DEP", "FEATURE"),
                        help="Find who requests FEATURE from DEP and trace them "
                             "to workspace members")
    parser.add_argument("--fedora-repo", metavar="REPO", default="rawhide",
                        help="DNF repository to query for Fedora Rust packages "
                             "(default: rawhide; pass empty string to skip)")
    args = parser.parse_args()

    print("Running `cargo metadata`…", file=sys.stderr)
    meta = cargo_metadata()
    print("Analysing dependency graph…", file=sys.stderr)
    result          = analyse(meta)

    # ── investigation-only modes (skip the full report) ──────────────────────
    if args.who_needs:
        target  = args.who_needs.lower()
        matches = {pid: label for pid, label in result["id_to_label"].items()
                   if target in label.lower()}
        if not matches:
            print(f"No package matching '{target}' found in lock file.")
            return
        for pid, label in matches.items():
            deps = who_requires(pid, result)
            print(f"\n{label} is required by:")
            for d in deps:
                print(f"  • {d}")
        return

    if args.why:
        print_why(args.why, meta, result)
        return

    if args.trace_feature:
        dep_name, feature = args.trace_feature
        print_trace_feature(dep_name, feature, meta, result)
        return

    feature_findings = analyse_features(meta, result)
    cross_table      = cross_crate_feature_table(feature_findings)
    dev_sources      = compute_dev_sources(result, meta)
    feat_sugg        = build_feature_suggestions(feature_findings)

    fedora_coverage = None
    if args.fedora_repo:
        fedora_crates = query_fedora_crates(args.fedora_repo)
        if fedora_crates:
            fedora_coverage = analyse_fedora_coverage(result, meta, fedora_crates)

    if args.json:
        out = {k: v for k, v in result.items()
               if k not in ("packages", "id_to_label", "node_deps",
                            "dev_only_ids", "compiled_ids")}
        # heaviness tuples are (compiled_count, raw_count, label); convert to
        # dicts for readable JSON output.
        out["heaviness"] = [
            {"compiled": fc, "raw": rc, "label": lbl}
            for fc, rc, lbl in out.get("heaviness", [])
        ]
        # feat_sugg uses (dep_name, version) tuple keys — convert to strings.
        def _str_keys(d: dict) -> dict:
            return {f"{k[0]} v{k[1]}": v for k, v in d.items()}
        out["feature_analysis"]    = feature_findings
        out["cross_crate_features"] = cross_table
        out["dev_sources"]         = dev_sources
        out["feature_suggestions"] = {
            "redundant":         _str_keys(feat_sugg["redundant"]),
            "defaults_add":      _str_keys(feat_sugg["defaults_add"]),
            "defaults_add_noop": _str_keys(feat_sugg["defaults_add_noop"]),
            "extra_others":      _str_keys(feat_sugg["extra_others"]),
        }
        if fedora_coverage is not None:
            out["fedora_coverage"] = {
                "repo":         args.fedora_repo,
                "missing":      fedora_coverage["missing"],
                "version_only": fedora_coverage["version_only"],
                "present":      fedora_coverage["present"],
            }
        print(json.dumps(out, indent=2))
    else:
        print_report(result, feature_findings, cross_table,
                     dev_sources, feat_sugg, meta, args.verbose,
                     fedora_coverage=fedora_coverage,
                     fedora_repo=args.fedora_repo)


if __name__ == "__main__":
    main()
