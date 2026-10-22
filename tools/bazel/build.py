#!/usr/bin/env python3
"""Run the declared kernel build directly or in a disposable Linux worker."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import ssl
import subprocess
import sys
import urllib.request
import urllib.parse
import uuid

WORKER_IMAGE = "debian:trixie-20260918@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c"
# Existing AMD64 buildimage consumers inspect these literal launcher pins.
BAZEL_URL = "https://releases.bazel.build/8.5.1/release/bazel-8.5.1-linux-x86_64"
BAZEL_SHA256 = "61d89402f0368e64b6c827be5de79d8e65382e8124c3cbb97325611a1851392e"
ARCHITECTURES = {
    "amd64": {
        "machine": "x86_64", "platform": "x86_64_trixie",
        "bazel_url": BAZEL_URL, "bazel_sha256": BAZEL_SHA256,
    },
    "arm64": {
        "machine": "aarch64", "platform": "aarch64_trixie",
        "bazel_url": "https://releases.bazel.build/8.5.1/release/bazel-8.5.1-linux-arm64",
        "bazel_sha256": "b7f2a85595e8a87d54843bc656c1e379fd9b8c1b5f783dc41717c1d7eb7cc49f",
    },
}


def native_architecture(requested=None):
    host = os.uname()
    native = next((name for name, config in ARCHITECTURES.items()
                   if host.sysname == "Linux" and host.machine == config["machine"]), None)
    if native is None:
        raise ValueError("kernel source builds require native Linux AMD64 or ARM64 execution")
    if requested is not None and requested != native:
        raise ValueError("requested architecture must match the native Linux host")
    return native


def bazel_binary(directory, ca_bundle=None, architecture="amd64"):
    config = ARCHITECTURES[architecture]
    url = config["bazel_url"]
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ("bazel-8.5.1-" + architecture)
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == config["bazel_sha256"]:
        return path
    temporary = directory / ("bazel-download-" + uuid.uuid4().hex)
    try:
        context = ssl.create_default_context()
        if ca_bundle:
            context.load_verify_locations(cafile=str(ca_bundle))
        with urllib.request.urlopen(url, timeout=120, context=context) as response, temporary.open("wb") as out:
            while chunk := response.read(1024 * 1024):
                out.write(chunk)
        if hashlib.sha256(temporary.read_bytes()).hexdigest() != config["bazel_sha256"]:
            raise ValueError("Bazel executable checksum mismatch")
        temporary.chmod(0o755)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def execution_script(args, executable, workspace, work, repository_cache, *, direct=False):
    """Use the same Bazel configuration with paths visible to its executor."""
    config = ARCHITECTURES[args.architecture]
    platform = "@sonic_build_infra//platforms:" + config["platform"]
    def quote(path):
        return shlex.quote(str(path))
    bazel = [str(executable), "--nosystem_rc", "--nohome_rc", "--output_user_root=" + str(work / "output")]
    if args.java_trust_store:
        trust_store = args.java_trust_store.resolve() if direct else Path("/trust/cacerts")
        bazel.append("--host_jvm_args=-Djavax.net.ssl.trustStore=" + str(trust_store))
    disk_cache = str(args.disk_cache.resolve()) if direct and args.disk_cache else "/disk-cache" if args.disk_cache else ""
    common = [
        "--repository_cache=" + str(repository_cache), "--lockfile_mode=update",
        "--symlink_prefix=" + str(work / "bazel-"), "--disk_cache=" + disk_cache,
        # Download the tool tree before local execution: Bazel 8 lazy input
        # materialization mishandles nested directory aliases in Debian tools.
        "--remote_download_outputs=all",
        "--jobs=1", "--sandbox_default_allow_network=false",
        "--strategy=SonicKernelBuild=local",
        "--host_platform=" + platform,
        "--platforms=" + platform,
    ]
    if args.remote_cache:
        common += ["--remote_cache=" + args.remote_cache,
                   "--remote_upload_local_results=" + str(not args.remote_cache_read_only).lower()]
    if args.ca_bundle:
        ca_bundle = args.ca_bundle.resolve() if direct else Path("/trust/ca-bundle.pem")
        common += ["--repo_env=SSL_CERT_FILE=" + str(ca_bundle),
                   "--repo_env=REQUESTS_CA_BUNDLE=" + str(ca_bundle)]
    if args.distdir:
        common.append("--distdir=" + str(args.distdir.resolve() if direct else Path("/distdir")))
    for module, directory in args.module_override:
        common.append("--override_module=" + module + "=" + str(directory.resolve() if direct else Path("/module-overrides") / module))
    common += args.bazel_arg
    build = bazel + ["build"] + common + [
        "--execution_log_json_file=" + str(work / "execution.json"),
        "--profile=" + str(work / "profile.json.gz"), "--build_event_json_file=" + str(work / "bep.json"), args.target,
    ]
    query = bazel + ["cquery"] + common + ["--output=files", args.target]
    graph_options = [option for option in common if option.startswith((
        "--repository_cache=", "--repo_env=", "--distdir=", "--override_module=", "--registry=",
    ))]
    graph = bazel + ["mod", "graph"] + graph_options + [
        "--output=json", "--extension_info=hidden", "--lockfile_mode=off",
        "--color=no", "--curses=no",
    ]
    script = [
        "set -euo pipefail", "bazel_started=0", "cd -- " + quote(workspace),
        "export HOME=" + quote(work / "home"), "mkdir -p -- " + quote(work / "home"),
        '[[ "$(uname -m)" == ' + quote(config["machine"]) + " ]]",
        "cleanup() {",
        "  status=$?; trap - EXIT INT TERM",
    ]
    if direct:
        # Container removal used to terminate this private Bazel server. In
        # direct mode finish it before returning the work tree to the caller.
        script.append("  if (( bazel_started )); then " + shlex.join(bazel + ["shutdown"]) + " >/dev/null 2>&1 || { echo 'Bazel shutdown failed' >&2; status=1; }; fi")
        # The generated root-module lock lives outside the dedicated work tree.
        # With a private caller umask it otherwise becomes unreadable root:root.
        lock = quote(workspace / "MODULE.bazel.lock")
        script += [
            "  if [[ -L " + lock + " || ( -e " + lock + " && ! -f " + lock + " ) ]]; then echo 'Invalid generated module lock' >&2; status=1;",
            "  elif [[ -f " + lock + " ]]; then chown -h " + str(os.getuid()) + ":" + str(os.getgid()) + " -- " + lock + " || status=1; fi",
        ]
    script += [
        "  chown -hR " + str(os.getuid()) + ":" + str(os.getgid()) + " -- " + quote(work) + " || status=1",
        '  exit "$status"', "}", "trap cleanup EXIT",
        "trap 'exit 130' INT", "trap 'exit 143' TERM",
        "if [[ -L " + quote(work / "output") + " || ( -e " + quote(work / "output") + " && ! -d " + quote(work / "output") + " ) ]]; then echo 'Invalid Bazel output directory' >&2; exit 1; fi",
        "mkdir -p -- " + quote(work / "output"), "chown -hR 0:0 -- " + quote(work / "output"),
    ]
    if direct:
        script += [
            "if [[ -L " + lock + " || ( -e " + lock + " && ! -f " + lock + " ) ]]; then echo 'Invalid generated module lock' >&2; exit 1; fi",
            "(umask 022; mkdir -p -- " + " ".join(quote(path) for path in (repository_cache, args.disk_cache.resolve() if args.disk_cache else None) if path is not None) + ")",
            shlex.join([sys.executable, str(Path(__file__).with_name("direct_permissions.py").resolve()), str(work)]),
            "command -v xz >/dev/null || { echo 'Direct kernel execution requires xz in the build environment' >&2; exit 1; }",
        ]
    else:
        script += [
            "if ! command -v xz >/dev/null; then",
            "  apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update",
            "  DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y --no-install-recommends xz-utils",
            "fi",
        ]
    if args.ca_bundle:
        script += ["export SSL_CERT_FILE=" + quote(ca_bundle), "export REQUESTS_CA_BUNDLE=" + quote(ca_bundle)]
    script += [
        "bazel_started=1", shlex.join(build), shlex.join(query) + " > " + quote(work / "output-paths.relative.txt"),
        "set +e", shlex.join(graph) + " > " + quote(work / "module-graph.json") + " 2> " + quote(work / "module-graph.stderr"),
        "graph_status=$?", "set -e",
        "printf '%s\\n' \"$graph_status\" > " + quote(work / "module-graph.exit-code"),
        'execution_root=$(dirname "$(realpath ' + quote(work / "bazel-out") + ')")',
        'while IFS= read -r output; do realpath "$execution_root/$output"; done < ' + quote(work / "output-paths.relative.txt") + " > " + quote(work / "output-paths.txt"),
    ]
    return "\n".join(script)


def worker_command(args, executable, name):
    workspace, work = args.workspace.resolve(), args.work_dir.resolve()
    repository_cache = (args.repository_cache or work / "repository-cache").resolve()
    repository_cache.mkdir(parents=True, exist_ok=True)
    script = execution_script(args, Path("/usr/local/bin/bazel"), Path("/workspace"), Path("/work"), Path("/repository-cache"))
    docker = [
        "docker", "run", "--rm", "--init", "--name", name, "--platform=linux/" + args.architecture,
        "--cpus=4", "--memory=12g", "--memory-swap=12g", "--network=host",
        "--workdir=/workspace", "--user=0:0",
        "--mount", "type=bind,src=" + str(workspace) + ",dst=/workspace",
        "--mount", "type=bind,src=" + str(work) + ",dst=/work",
        "--mount", "type=bind,src=" + str(repository_cache) + ",dst=/repository-cache",
        "--mount", "type=bind,src=" + str(executable) + ",dst=/usr/local/bin/bazel,readonly",
    ]
    if args.disk_cache:
        args.disk_cache.mkdir(parents=True, exist_ok=True)
        docker += ["--mount", "type=bind,src=" + str(args.disk_cache.resolve()) + ",dst=/disk-cache"]
    for module, directory in args.module_override:
        docker += ["--mount", "type=bind,src=" + str(directory.resolve()) + ",dst=/module-overrides/" + module + ",readonly"]
    for source, target in ((args.java_trust_store, "/trust/cacerts"),
                           (args.ca_bundle, "/trust/ca-bundle.pem"), (args.distdir, "/distdir")):
        if source:
            docker += ["--mount", "type=bind,src=" + str(source.resolve()) + ",dst=" + target + ",readonly"]
    if args.ca_bundle:
        docker += ["--env=SSL_CERT_FILE=/trust/ca-bundle.pem", "--env=REQUESTS_CA_BUNDLE=/trust/ca-bundle.pem"]
    return docker + [args.worker_image, "/bin/bash", "-c", script]


def direct_command(args, executable):
    work = args.work_dir.resolve()
    repository_cache = (args.repository_cache or work / "repository-cache").resolve()
    script = execution_script(args, executable, args.workspace.resolve(), work, repository_cache, direct=True)
    command = ["/bin/bash", "-c", script]
    if os.geteuid() != 0:
        # SONiC's builder user has noninteractive sudo. Preserve fetch proxies,
        # not arbitrary caller configuration or credentials, across elevation.
        command = ["sudo", "-n", "--preserve-env=http_proxy,https_proxy,no_proxy,HTTP_PROXY,HTTPS_PROXY,NO_PROXY", "--"] + command
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--repository-cache", type=Path)
    parser.add_argument("--disk-cache", type=Path)
    parser.add_argument("--remote-cache")
    parser.add_argument("--remote-cache-read-only", action="store_true")
    parser.add_argument("--target", default="@sonic_linux_kernel//:kernel_packages")
    parser.add_argument("--execution-mode", choices=("container", "direct"), default="container",
                        help="use a disposable worker, or root/noninteractive sudo in the existing build environment")
    parser.add_argument("--worker-image", default=WORKER_IMAGE)
    parser.add_argument("--architecture", choices=tuple(ARCHITECTURES),
                        help="native build architecture (defaults to the Linux host architecture)")
    parser.add_argument("--bazel-arg", action="append", default=[])
    parser.add_argument("--module-override", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--java-trust-store", type=Path)
    parser.add_argument("--ca-bundle", type=Path)
    parser.add_argument("--distdir", type=Path)
    args = parser.parse_args()
    try:
        args.architecture = native_architecture(args.architecture)
    except ValueError as error:
        parser.error(str(error))
    if args.execution_mode == "direct" and args.worker_image != WORKER_IMAGE:
        parser.error("--worker-image applies only to container execution")
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64}", args.worker_image):
        parser.error("--worker-image requires an immutable image digest")
    if not (args.workspace / "MODULE.bazel").is_file():
        parser.error("--workspace must contain MODULE.bazel")
    workspace, work = args.workspace.resolve(), args.work_dir.resolve()
    if work in (Path("/"), Path("/tmp"), Path("/home"), Path.home()) or work == workspace or work in workspace.parents:
        parser.error("--work-dir must be a dedicated directory that does not contain the source workspace")
    for cache in (args.repository_cache, args.disk_cache):
        if cache and cache.resolve() in (Path("/"), Path("/tmp"), Path("/home"), Path.home(), workspace):
            parser.error("cache paths must name dedicated cache directories")
    if args.remote_cache:
        endpoint = urllib.parse.urlsplit(args.remote_cache)
        if endpoint.scheme not in ("http", "https", "grpc", "grpcs") or not endpoint.hostname:
            parser.error("remote cache must be an HTTP(S) or gRPC(S) endpoint")
        if endpoint.username is not None or endpoint.password is not None or endpoint.query or endpoint.fragment:
            parser.error("remote cache URL must not contain credentials, query parameters, or fragments")
    for path in (args.java_trust_store, args.ca_bundle):
        if path and not path.is_file():
            parser.error("trust inputs must name existing public certificate files")
    if args.ca_bundle and "PRIVATE KEY" in args.ca_bundle.read_text():
        parser.error("CA bundle must not contain a private key")
    if args.distdir and not args.distdir.is_dir():
        parser.error("--distdir must name a source archive directory")
    overrides = []
    for override in args.module_override:
        name, separator, directory = override.partition("=")
        if not separator or not re.fullmatch(r"[a-z][a-z0-9._-]*", name):
            parser.error("--module-override requires NAME=PATH")
        directory = Path(directory).resolve()
        if not (directory / "MODULE.bazel").is_file():
            parser.error("module override must contain MODULE.bazel")
        if directory == work or work in directory.parents:
            parser.error("--work-dir must not contain a module source override")
        overrides.append((name, directory))
    args.module_override = overrides
    args.work_dir.mkdir(parents=True, exist_ok=True)
    executable = bazel_binary(args.work_dir / "bootstrap", args.ca_bundle, args.architecture).resolve()
    name = "sonic-kernel-bazel-" + uuid.uuid4().hex[:16]
    command = direct_command(args, executable) if args.execution_mode == "direct" else worker_command(args, executable, name)
    (args.work_dir / "invocation.json").write_text(json.dumps({
        "schema": 1, "execution_mode": args.execution_mode,
        "worker": args.worker_image if args.execution_mode == "container" else None, "target": args.target,
        "workspace": str(workspace), "work_dir": str(work), "execution_uid": 0,
        "caller_uid": os.getuid(), "caller_gid": os.getgid(),
        "repository_cache": str((args.repository_cache or work / "repository-cache").resolve()),
        "architecture": args.architecture, "host_machine": os.uname().machine,
        "remote_cache": args.remote_cache, "remote_cache_read_only": args.remote_cache_read_only,
        "disk_cache": str(args.disk_cache.resolve()) if args.disk_cache else None,
    }, indent=2) + "\n")
    process = None
    previous_term = signal.getsignal(signal.SIGTERM)
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with (args.work_dir / "build.log").open("w") as log:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
            for line in process.stdout:
                log.write(line)
                log.flush()
                sys.stdout.write(line)
                sys.stdout.flush()
            return process.wait()
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        if process is not None and process.poll() is None:
            if args.execution_mode == "container":
                subprocess.run(["docker", "stop", "--time=20", name], check=False)
            else:
                os.killpg(process.pid, signal.SIGTERM)
            process.wait()
        if process is not None and process.stdout is not None:
            process.stdout.close()


if __name__ == "__main__":
    sys.exit(main())
