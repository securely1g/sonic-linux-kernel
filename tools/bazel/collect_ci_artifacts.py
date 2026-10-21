#!/usr/bin/env python3
"""Create the bounded public artifact set for kernel source/cache CI."""

import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kernel_action

MANIFEST = kernel_action.MANIFEST
PACKAGE_KEYS = {"name", "kind", "package", "version", "architecture", "sha256", "size"}
MANIFEST_KEYS = {
    "schema", "architecture", "platform", "kernel_version", "kernel_abi",
    "package_version", "signing", "source_date_epoch", "source_archives",
    "source_tree_sha256", "source_files", "build_tools", "packages", "created_packages", "debug",
}
CONFIGURATION = {
    "schema": 3, "architecture": "amd64", "platform": "vs", "kernel_version": "6.12.41",
    "kernel_abi": "6.12.41+deb13-sonic-amd64", "package_version": "6.12.41-1",
    "signing": "unsigned", "source_date_epoch": kernel_action.SOURCE_DATE_EPOCH,
}
PUBLIC_REGISTRIES = {
    "https://bcr.bazel.build/modules/": "bazel-central",
    "https://raw.githubusercontent.com/securely1g/sonic-bazel-registry/main/modules/": "sonic-main",
}
PRIVATE_FILES = {
    **{run + "_" + label: run + "/" + name for run in ("cold", "hit") for label, name in (
        ("build_log", "build.log"), ("execution", "execution.json"), ("bep", "bep.json"),
        ("profile", "profile.json.gz"), ("invocation", "invocation.json"),
        ("module_graph", "module-graph.json"),
    )},
    "cold_lock": "cold-consumer/MODULE.bazel.lock",
    "hit_lock": "hit-consumer/MODULE.bazel.lock",
    "cache_log": "cache.log", "cache_proof": "verified/cache-proof.json",
    "installed_debugger": "debugger.json", "installed_packages": "installation.json",
}
DIGEST = re.compile(r"[0-9a-f]{64}")
MODULE_NAME = re.compile(r"[a-z][a-z0-9._-]{0,127}")
MODULE_VERSION = re.compile(r"[0-9][A-Za-z0-9.+_-]{0,127}")


def configuration(architecture):
    return {**CONFIGURATION, "architecture": architecture,
            "kernel_abi": kernel_action.kernel_abi(architecture)}


class CollectionError(ValueError):
    """A fixed-message artifact policy failure."""


def require(condition, message):
    if not condition:
        raise CollectionError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value):
    raise CollectionError("non-finite JSON number")


def file_at(root, relative, *, optional=False):
    root = Path(root)
    require(not root.is_symlink(), "unsafe evidence root")
    if optional and not root.exists():
        return None
    require(root.is_dir(), "missing evidence root")
    path = root
    for part in Path(relative).parts:
        require(part not in ("", ".", ".."), "unsafe evidence path")
        path = path / part
        require(not path.is_symlink(), "unsafe evidence path")
    if optional and not path.exists():
        return None
    require(path.is_file() and path.resolve().is_relative_to(root.resolve()), "missing regular evidence file")
    return path


def read_json(path, limit):
    require(path.stat().st_size <= limit, "evidence JSON exceeds size limit")
    return json.loads(path.read_text(), object_pairs_hook=unique_object, parse_constant=reject_constant)


def git(source, *arguments):
    result = subprocess.run(["git", "-C", str(source), *arguments], capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, "source checkout verification failed")
    return result.stdout.strip()


def checkout_inputs(source):
    """Bind public manifest paths and archive records to the checked-out source."""
    source = Path(source).resolve(strict=True)
    selected = ["Makefile", "manage-config", "config.local", "patches-debian", "patches-sonic",
                *kernel_action.EXTRA_SOURCES]
    revision = git(source, "rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "invalid source revision")
    git(source, "diff", "--quiet", "HEAD", "--", *selected, "tools/bazel/sources.bzl")
    tracked = set(git(source, "ls-files", "--", *selected).splitlines())
    actual = set()
    for name in selected:
        path = source / name
        if path.is_dir():
            actual.update(str(child.relative_to(source)) for child in path.rglob("*") if child.is_file())
        else:
            actual.add(name)
    require(actual == tracked, "source inventory differs from the checked-out revision")
    inventory = kernel_action.source_inventory([
        {"name": name, "path": str(file_at(source, name))} for name in sorted(actual)
    ])
    tree = ast.parse(file_at(source, "tools/bazel/sources.bzl").read_text())
    declarations = [node.value for node in tree.body if isinstance(node, ast.Assign)
                    and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "KERNEL_SOURCES"]
    require(len(declarations) == 1 and isinstance(declarations[0], ast.Dict), "invalid source archive declarations")
    archives = []
    for value in declarations[0].values:
        require(isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id == "struct" and not value.args, "invalid source archive declarations")
        fields = {item.arg: ast.literal_eval(item.value) for item in value.keywords}
        require(set(fields) == {"name", "sha256"} and isinstance(fields["name"], str)
                and isinstance(fields["sha256"], str) and DIGEST.fullmatch(fields["sha256"]),
                "invalid source archive declarations")
        archives.append(fields)
    require(len(archives) == 3 and {item["name"] for item in archives} == {
        "linux_6.12.41-1.dsc", "linux_6.12.41.orig.tar.xz", "linux_6.12.41-1.debian.tar.xz",
    }, "unexpected source archive set")
    return revision, inventory, sorted(archives, key=lambda item: item["name"])


def validate_package(record, architecture="amd64", *, created=False):
    expected = PACKAGE_KEYS | ({"exported"} if created else set())
    require(isinstance(record, dict) and set(record) == expected,
            "unexpected package record fields")
    require(isinstance(record["package"], str)
            and re.fullmatch(r"[a-z0-9][a-z0-9+.-]{1,127}", record["package"])
            and record["version"] == CONFIGURATION["package_version"]
            and record["architecture"] in (architecture, "all"),
            "unexpected Debian package identity")
    require(record["name"] == "_".join(record[key] for key in ("package", "version", "architecture")) + ".deb",
            "package filename differs from its identity")
    kinds = kernel_action.package_kinds(architecture)
    require(record["kind"] == kinds.get(record["name"], "other")
            and (created or record["name"] in kinds), "unexpected package name or kind")
    if created:
        require(record["exported"] is (record["name"] in kinds), "invalid created-package export marker")
    require(type(record["size"]) is int and 0 < record["size"] <= 2**40
            and isinstance(record["sha256"], str) and DIGEST.fullmatch(record["sha256"]),
            "invalid package size or digest")


def validate_payload(archive, kind, architecture="amd64", *, debugger_sources=()):
    """Inspect the decoded Debian payload without extracting or executing it."""
    names, regular, symlinks, hardlinks, modules = set(), set(), {}, {}, set()
    abi = configuration(architecture)["kernel_abi"]
    for member in archive:
        raw = PurePosixPath(member.name)
        require(not raw.is_absolute() and ".." not in raw.parts, "unsafe package member path")
        name = str(raw)
        if name == ".":
            require(member.isdir(), "invalid package root")
            continue
        require(name not in names, "duplicate package member")
        names.add(name)
        require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                "unsupported package member type")
        require(member.uid == 0 and member.gid == 0 and not member.mode & 0o6000,
                "unsafe package ownership or permissions")
        if member.issym() or member.islnk():
            require(member.linkname and "\x00" not in member.linkname, "invalid package link")
            target = PurePosixPath(member.linkname)
            if member.islnk():
                require(not target.is_absolute() and ".." not in target.parts,
                        "unsafe package hardlink")
                hardlinks[name] = str(target)
            else:
                # Header links may be absolute in the installed filesystem.
                # A relative link may climb only within that installation root.
                parts = [] if target.is_absolute() else list(raw.parent.parts)
                for part in target.parts:
                    if part in ("/", "."):
                        continue
                    if part == "..":
                        require(parts, "package link escapes installation root")
                        parts.pop()
                    else:
                        parts.append(part)
                symlinks[name] = "/".join(parts)
        if member.isfile():
            regular.add(name)
    require(not any(str(parent) in symlinks or str(parent) in hardlinks or str(parent) in regular
                    for name in names for parent in PurePosixPath(name).parents),
            "package member descends through a non-directory")
    require(all(target in regular for target in hardlinks.values()),
            "package hardlink does not name a regular payload file")
    regular.update(hardlinks)
    modules = {name for name in regular if re.search(r"\.ko(?:\.xz|\.gz|\.zst)?$", name)}
    if kind == "runtime":
        required = {"boot/vmlinuz-" + abi, "boot/config-" + abi}
        require(required <= regular and modules, "runtime package lacks kernel or modules")
        require(all(name.startswith(("lib/modules/" + abi + "/", "usr/lib/modules/" + abi + "/"))
                    for name in modules), "runtime package contains modules for another ABI")
        require(not any(name.startswith("usr/lib/debug/") for name in regular),
                "debug payload in runtime package")
        device_trees = {name for name in regular if name.endswith((".dtb", ".dtbo"))}
        require(all(name.startswith("usr/lib/linux-image-" + abi + "/") for name in device_trees),
                "runtime package contains device trees for another ABI")
        if architecture == "arm64":
            require(any(name.endswith(".dtb") for name in device_trees),
                    "ARM64 runtime package lacks device trees")
    elif kind == "debug":
        require("usr/lib/debug/boot/vmlinux-" + abi in regular and modules,
                "debug package lacks kernel symbols or modules")
        require(all("usr/src/debug/linux-" + abi + "/" + name in regular for name in debugger_sources),
                "debugger source is absent from the debug package")
        require(all(name.startswith("usr/lib/debug/") and name.endswith(".ko") for name in modules),
                "debug package contains misplaced or compressed modules")
        require(all(name.startswith(("usr/lib/debug/", "usr/share/doc/", "usr/src/debug/linux-" + abi + "/"))
                    or name == "usr/share/lintian/overrides/linux-image-" + abi + "-dbg"
                    for name in regular), "runtime payload in debug package")
    elif kind == "headers":
        headers = "usr/src/linux-headers-" + abi + "/"
        require({headers + ".config", headers + "Module.symvers", headers + "Makefile"} <= regular,
                "headers package lacks usable configured headers")
        require(not modules, "runtime modules in headers package")
    elif kind == "headers_common":
        headers = "usr/src/linux-headers-6.12.41+deb13-common-sonic/"
        require(headers + "Makefile" in regular and any(name.startswith(headers + "include/") for name in regular),
                "common headers package lacks source headers")
        require(not modules, "runtime modules in common headers package")
    elif kind == "kbuild":
        require("usr/lib/linux-kbuild-6.12.41+deb13/scripts/mod/modpost" in regular,
                "kbuild package lacks module build tools")
        require(not modules, "runtime modules in kbuild package")
    else:
        raise CollectionError("unexpected package kind")
    return modules


def validate_deb(path, record, architecture="amd64", *, debugger_sources=()):
    """Use dpkg's decoder for both control metadata and the filesystem stream."""
    validate_package(record, architecture)
    control = subprocess.run([
        "dpkg-deb", "--show", "--showformat=${Package}\n${Version}\n${Architecture}\n", str(path),
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=60)
    require(control.returncode == 0 and control.stdout.splitlines()
            == [record[key] for key in ("package", "version", "architecture")],
            "Debian control identity differs from manifest")
    process = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            modules = validate_payload(archive, record["kind"], architecture, debugger_sources=debugger_sources)
        # Consume trailing TAR padding before waiting, so a full pipe cannot
        # deadlock dpkg-deb after the TAR end marker.
        for _chunk in iter(lambda: process.stdout.read(1024 * 1024), b""):
            pass
        require(process.wait(timeout=60) == 0, "Debian package payload could not be decoded")
        return modules
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
        process.wait()


def validate_manifest(manifest, inventory, archives, architecture="amd64"):
    require(isinstance(manifest, dict) and set(manifest) == MANIFEST_KEYS, "unexpected manifest fields")
    require(all(type(manifest[key]) is type(value) and manifest[key] == value
                for key, value in configuration(architecture).items()),
            "manifest differs from the supported kernel configuration")
    require(manifest["source_files"] == inventory
            and manifest["source_tree_sha256"] == kernel_action.source_tree_sha256(inventory)
            and manifest["source_archives"] == archives, "manifest source inputs differ from the checkout")
    tools = manifest["build_tools"]
    require(isinstance(tools, dict) and set(tools) == {
        "schema_version", "kind", "architecture", "identity_sha256", "input_sha256", "packages",
    }, "unexpected build-tools fields")
    inputs = tools["input_sha256"]
    require(type(tools["schema_version"]) is int and tools["schema_version"] == 1
            and tools["kind"] == "debian-build-tools" and tools["architecture"] == architecture
            and isinstance(inputs, list) and 0 < len(inputs) <= 4096
            and all(isinstance(value, str) and DIGEST.fullmatch(value) for value in inputs)
            and inputs == sorted(inputs), "invalid build-tools identity")
    expected_identity = hashlib.sha256(json.dumps({"architecture": architecture, "inputs": inputs}, sort_keys=True).encode()).hexdigest()
    require(tools["identity_sha256"] == expected_identity, "build-tools identity differs from its inputs")
    packages = tools["packages"]
    require(isinstance(packages, dict) and 0 < len(packages) <= 4096 and all(
        isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", name)
        and isinstance(version, str) and re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,127}", version)
        for name, version in packages.items()), "invalid build-tools package inventory")
    records = manifest["packages"]
    require(isinstance(records, list) and len(records) == 5, "expected five exported Debian packages")
    for record in records:
        validate_package(record, architecture)
    require(records == sorted(records, key=lambda item: item["name"])
            and {item["name"] for item in records} == kernel_action.package_names(architecture),
            "unexpected exported package set")
    created = manifest["created_packages"]
    require(isinstance(created, list) and 5 <= len(created) <= 256, "invalid created-package inventory")
    for record in created:
        validate_package(record, architecture, created=True)
    require(created == sorted(created, key=lambda item: item["name"])
            and len({item["name"] for item in created}) == len(created)
            and [{key: value for key, value in item.items() if key != "exported"}
                 for item in created if item["exported"]] == records,
            "created and exported package inventories differ")
    debug = manifest["debug"]
    require(isinstance(debug, dict) and set(debug) == {
        "kernel_build_id", "module_count", "module_build_ids_sha256",
    }, "unexpected debug verification fields")
    require(isinstance(debug["kernel_build_id"], str)
            and re.fullmatch(r"[0-9a-f]{8,128}", debug["kernel_build_id"])
            and type(debug["module_count"]) is int and debug["module_count"] > 0
            and isinstance(debug["module_build_ids_sha256"], str)
            and DIGEST.fullmatch(debug["module_build_ids_sha256"]), "invalid debug verification")


def public_debugger(private, architecture="amd64"):
    result = read_json(file_at(private, "debugger.json"), 16 * 1024)
    require(isinstance(result, dict) and set(result) == {"schema", "result", "architecture", "gdb", "kernel", "module"}
            and type(result["schema"]) is int and result["schema"] == 1 and result["result"] == "passed"
            and result["architecture"] == architecture,
            "installed debugger verification did not pass")
    require(isinstance(result["gdb"], str) and re.fullmatch(
        r"GNU gdb(?: \([A-Za-z0-9 .+~:-]{1,128}\))? [0-9][A-Za-z0-9.+~:-]{0,63}", result["gdb"]),
        "invalid debugger version")
    for kind in ("kernel", "module"):
        record = result[kind]
        expected = {"function", "source", "line", "type_lookup"} | ({"path"} if kind == "module" else set())
        require(isinstance(record, dict) and set(record) == expected, "unexpected debugger record fields")
        require(isinstance(record["function"], str)
                and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,127}", record["function"])
                and (kind != "kernel" or record["function"] == "start_kernel")
                and type(record["line"]) is int and 0 < record["line"] <= 10000000
                and record["type_lookup"] is (kind == "kernel"), "invalid debugger symbol result")
        for key in (("source", "path") if kind == "module" else ("source",)):
            path = record[key]
            require(isinstance(path, str) and re.fullmatch(r"[A-Za-z0-9_+./-]{1,512}", path)
                    and not PurePosixPath(path).is_absolute() and ".." not in PurePosixPath(path).parts,
                    "unsafe debugger result path")
        if kind == "module":
            require(record["path"].startswith("kernel/") and record["path"].endswith(".ko"),
                    "invalid debugger module path")
    return result


def public_installation(private, packages, architecture="amd64"):
    result = read_json(file_at(private, "installation.json"), 16 * 1024)
    require(isinstance(result, dict) and set(result) == {
        "schema", "result", "architecture", "installed_packages", "initramfs", "external_module", "module_vermagic",
    } and type(result["schema"]) is int and result["schema"] == 1
            and result["result"] == "passed" and result["architecture"] == architecture
            and result["initramfs"] is True and result["external_module"] is True,
            "installed Debian package verification did not pass")
    expected = sorted([
        {**{key: record[key] for key in ("package", "version", "architecture")}, "status": "install ok installed"}
        for record in packages
    ], key=lambda item: item["package"])
    require(result["installed_packages"] == expected, "installed Debian identities differ from exported packages")
    vermagic = result["module_vermagic"]
    require(isinstance(vermagic, str) and re.fullmatch(r"[A-Za-z0-9_+. -]{1,256}", vermagic)
            and vermagic.split() and vermagic.split()[0] == configuration(architecture)["kernel_abi"],
            "installed header module has unexpected vermagic")
    return result


def safe_metrics(value):
    if not isinstance(value, dict):
        return {}
    result = {}
    for name in ("totalTime", "executionWallTime", "fetchTime", "setupTime"):
        duration = value.get(name)
        if isinstance(duration, str) and re.fullmatch(r"[0-9]{1,9}(?:\.[0-9]{1,9})?s", duration):
            result[name] = duration
    for name in ("inputFiles", "inputBytes"):
        count = value.get(name)
        if isinstance(count, str) and re.fullmatch(r"[0-9]{1,20}", count):
            result[name] = int(count)
    return result


def public_proof(private, architecture="amd64"):
    proof = read_json(file_at(private, "verified/cache-proof.json"), 1024 * 1024)
    require(isinstance(proof, dict) and type(proof.get("schema")) is int and proof["schema"] == 1
            and proof.get("result") == "passed" and proof.get("cold_compiled") is True
            and proof.get("consumer_kernel_runner") == "remote cache hit"
            and proof.get("consumer_kernel_cache_hit") is True and proof.get("kernel_compilation_skipped") is True
            and proof.get("architecture") == architecture,
            "cache verification did not pass")
    hashes = proof.get("outputs_sha256")
    names = kernel_action.package_names(architecture) | {MANIFEST}
    require(isinstance(hashes, dict) and set(hashes) == names and all(
        isinstance(value, str) and DIGEST.fullmatch(value) for value in hashes.values()), "invalid cache output digests")
    return {
        "architecture": architecture, "cold_compiled": True, "consumer_kernel_runner": "remote cache hit",
        "consumer_kernel_cache_hit": True, "kernel_compilation_skipped": True,
        "outputs_sha256": hashes, "cold_metrics": safe_metrics(proof.get("cold_metrics")),
        "hit_metrics": safe_metrics(proof.get("hit_metrics")),
    }


def registry_files(lock):
    require(isinstance(lock, dict) and type(lock.get("lockFileVersion")) is int
            and 0 < lock["lockFileVersion"] <= 1000 and isinstance(lock.get("registryFileHashes"), dict)
            and isinstance(lock.get("moduleExtensions"), dict), "invalid generated module lock")
    entries = {}
    for url, digest in lock["registryFileHashes"].items():
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            continue
        for prefix, registry in PUBLIC_REGISTRIES.items():
            if isinstance(url, str) and url.startswith(prefix):
                parts = url[len(prefix):].split("/")
                if (len(parts) == 3 and MODULE_NAME.fullmatch(parts[0]) and MODULE_VERSION.fullmatch(parts[1])
                        and parts[2] in ("MODULE.bazel", "source.json")):
                    entries.setdefault((parts[0], parts[1]), {}).setdefault(parts[2], []).append((registry, digest))
                break
    return entries


def redacted_resolution(private, run):
    lock = read_json(file_at(private, run + "-consumer/MODULE.bazel.lock"), 128 * 1024 * 1024)
    entries = registry_files(lock)
    graph = read_json(file_at(private, run + "/module-graph.json"), 16 * 1024 * 1024)
    exit_text = file_at(private, run + "/module-graph.exit-code").read_text().strip()
    require(exit_text == "0", "module graph inspection did not complete")
    require(isinstance(graph, dict) and graph.get("key") == "<root>" and graph.get("root") is True
            and graph.get("name") == "sonic-kernel-cache-consumer" and graph.get("version") == "",
            "invalid module graph root")
    queue = [(None, None, graph)]
    nodes, edges, referenced, expanded = {}, set(), set(), set()
    occurrences = 0
    while queue:
        parent, relation, node = queue.pop()
        occurrences += 1
        require(occurrences <= 10000 and isinstance(node, dict), "invalid module graph")
        key, name, version = node.get("key"), node.get("name"), node.get("version")
        require(isinstance(name, str) and MODULE_NAME.fullmatch(name) and isinstance(version, str), "invalid module identity")
        if key == "<root>":
            require(name == "sonic-kernel-cache-consumer" and version == "", "invalid local module identity")
        elif name == "sonic-linux-kernel":
            require(MODULE_VERSION.fullmatch(version) and key in (name + "@_", name + "@" + version), "invalid local module identity")
        else:
            require(MODULE_VERSION.fullmatch(version) and key == name + "@" + version, "invalid public module identity")
        require(key not in nodes or nodes[key] == (name, version), "inconsistent module graph identity")
        nodes[key] = (name, version)
        referenced.add(key)
        require(type(node.get("unexpanded", False)) is bool, "invalid module graph expansion marker")
        if not node.get("unexpanded", False):
            expanded.add(key)
        if parent is not None:
            edges.add((parent, key, relation))
        for field in ("dependencies", "indirectDependencies", "cycles"):
            children = node.get(field, [])
            require(isinstance(children, list), "invalid module graph edges")
            queue.extend((key, field, child) for child in children)
    require(referenced == expanded and len(nodes) > 2
            and sum(name == "sonic-linux-kernel" for name, _version in nodes.values()) == 1,
            "incomplete module graph")
    public_nodes, selected_files = [], 0
    identifiers = {key: ("<root>" if key == "<root>" else name + "@" + version)
                   for key, (name, version) in nodes.items()}
    for key, (name, version) in sorted(nodes.items(), key=lambda item: identifiers[item[0]]):
        record = {"name": name, "version": version}
        if key == "<root>":
            record["source_kind"] = "workspace"
        elif name == "sonic-linux-kernel":
            record["source_kind"] = "local_override"
        else:
            files = entries.get((name, version), {})
            module_files, source_files = files.get("MODULE.bazel", []), files.get("source.json", [])
            require(len(module_files) == 1 and len(source_files) <= 1, "selected module has no unique public registry record")
            registry, digest = module_files[0]
            record.update({"source_kind": "public_registry", "registry": registry, "module_sha256": digest})
            selected_files += 1
            if source_files:
                require(source_files[0][0] == registry, "selected module registry records disagree")
                record["source_sha256"] = source_files[0][1]
                selected_files += 1
        public_nodes.append(record)
    public_edges = [{"from": identifiers[parent], "to": identifiers[child], "relation": relation}
                    for parent, child, relation in sorted(edges)]
    summary = {
        "lock_file_version": lock["lockFileVersion"], "graph_exit_code": 0,
        "module_extension_state_count": len(lock["moduleExtensions"]),
        "omitted_registry_entry_count": len(lock["registryFileHashes"]) - selected_files,
    }
    return {"modules": public_nodes, "edges": public_edges}, summary


def write_json(directory, name, value):
    path = directory / name
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def collect(private, source, output, job_status, architecture="amd64"):
    expected_configuration = configuration(architecture)
    private, output = Path(private), Path(output)
    require(job_status in ("success", "failure", "cancelled"), "invalid job status")
    require(not output.exists() and not output.is_symlink(), "artifact destination already exists")
    require(output.parent.is_dir() and not output.resolve().is_relative_to(private.resolve()), "invalid artifact destination")
    presence = {name: file_at(private, relative, optional=True) is not None for name, relative in PRIVATE_FILES.items()}
    temporary = Path(tempfile.mkdtemp(prefix=".kernel-artifacts-", dir=output.parent))
    try:
        validation = {
            "schema": 1, "artifact_policy": "allowlisted-kernel-ci-v3", "job_status": job_status,
            "result": "incomplete", "artifacts_published": False, "private_evidence_present": presence,
        }
        if job_status == "success":
            revision, inventory, archives = checkout_inputs(source)
            manifest_path = file_at(private, "verified/" + MANIFEST)
            manifest = read_json(manifest_path, 4 * 1024 * 1024)
            validate_manifest(manifest, inventory, archives, architecture)
            proof = public_proof(private, architecture)
            debugger = public_debugger(private, architecture)
            installation = public_installation(private, manifest["packages"], architecture)
            module_sets = {}
            for name in sorted(kernel_action.package_names(architecture) | {MANIFEST}):
                path = file_at(private, "verified/" + name)
                require(kernel_action.sha256(path) == proof["outputs_sha256"][name], "verified output digest differs")
                if name != MANIFEST:
                    record = next(item for item in manifest["packages"] if item["name"] == name)
                    require(path.stat().st_size == record["size"] and proof["outputs_sha256"][name] == record["sha256"],
                            "verified artifact differs from manifest")
                    module_sets[record["kind"]] = validate_deb(
                        path, record, architecture,
                        debugger_sources=[debugger[key]["source"] for key in ("kernel", "module")])
                destination = temporary / name
                shutil.copyfile(path, destination)
                destination.chmod(0o600)
                require(kernel_action.sha256(destination) == proof["outputs_sha256"][name], "copied output digest differs")
            runtime_modules = {re.sub(r"\.(xz|gz|zst)$", "", name.removeprefix("usr/")).removeprefix("lib/modules/")
                               for name in module_sets["runtime"]}
            debug_modules = {name.removeprefix("usr/lib/debug/lib/modules/")
                             for name in module_sets["debug"]}
            require(runtime_modules == debug_modules and len(runtime_modules) == manifest["debug"]["module_count"],
                    "runtime and debug module inventories differ")
            expected_debug_module = expected_configuration["kernel_abi"] + "/" + debugger["module"]["path"]
            require(expected_debug_module in debug_modules, "debugger module is absent from debug package")
            cold, cold_summary = redacted_resolution(private, "cold")
            hit, hit_summary = redacted_resolution(private, "hit")
            require(cold == hit, "selected source and consumer module resolution differs")
            resolution = {
                "schema": 1, "kind": "allowlisted-generated-bazel-resolution",
                "module_graph_complete": True, "selected_module_resolution_equal": True,
                "module_extension_state_redacted": True, "cold": cold_summary, "hit": hit_summary,
                **cold,
            }
            write_json(temporary, "resolution.json", resolution)
            validation.update({
                "result": "passed", "artifacts_published": True, "checkout_revision": revision,
                "configuration": {**expected_configuration, "distribution": "trixie", "target": "@sonic_linux_kernel//:kernel_packages"},
                "cache_proof": proof, "debugger": debugger, "installation": installation,
                "selected_module_count": len(cold["modules"]),
            })
        write_json(temporary, "validation.json", validation)
        require(not output.exists() and not output.is_symlink(), "artifact destination appeared during collection")
        temporary.rename(output)
        return {"result": validation["result"], "published_file_count": len(list(output.iterdir()))}
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--job-status", required=True, choices=("success", "failure", "cancelled"))
    parser.add_argument("--architecture", choices=("amd64", "arm64"), default="amd64")
    args = parser.parse_args()
    try:
        result = collect(args.private_root, args.source_root, args.output, args.job_status, args.architecture)
    except Exception:
        # Exception details can contain untrusted paths or JSON values. Keep CI
        # output fixed; the failed collector is never followed by artifact upload.
        print("Kernel artifact collection failed; private evidence was not published.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
