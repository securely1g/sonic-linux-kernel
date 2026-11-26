"""Original Debian kernel sources, shared by standalone and image consumers."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
load("@sonic_build_infra//source:prepared_source.bzl", "prepared_source")
load("@sonic_build_infra//source:patch_tools.bzl", "patch_tools_repository")

KERNEL_SOURCES = {
    "kernel_dsc": struct(
        name = "linux_6.12.41-1.dsc",
        sha256 = "65bbf4e35635465326c9470605da1886ce3d3cf7e2a6d93392c4c6245d895b34",
    ),
    "kernel_orig": struct(
        name = "linux_6.12.41.orig.tar.xz",
        sha256 = "78afa637ca891174c22b332e4c1f87cf6aaa81861a6cca3b529e861843fa2fd3",
    ),
    "kernel_debian": struct(
        name = "linux_6.12.41-1.debian.tar.xz",
        sha256 = "b62680107fc155ad3d2c421ba0af1d5848812674fe767fcd40ba81a414e4ce2a",
    ),
}

def _source_urls(name):
    # Debian Snapshot retains the exact Makefile inputs after archive rotation.
    return [
        "https://snapshot.debian.org/archive/debian-security/20250813T110322Z/pool/updates/main/l/linux/" + name,
        "https://packages.trafficmanager.net/public/debian-security/pool/updates/main/l/linux/" + name,
    ]

def _kernel_sources_impl(module_ctx):
    for name, source in KERNEL_SOURCES.items():
        http_file(
            name = name,
            urls = _source_urls(source.name),
            downloaded_file_path = source.name,
            sha256 = source.sha256,
        )

    patch_tools_repository(name = "kernel_patch_tools", lock = "@sonic_build_infra//apt:apt.lock.json")
    steps = [
        json.encode({"op": "archive", "urls": _source_urls(KERNEL_SOURCES["kernel_orig"].name), "sha256": KERNEL_SOURCES["kernel_orig"].sha256, "strip_prefix": "linux-6.12.41"}),
        json.encode({"op": "archive", "urls": _source_urls(KERNEL_SOURCES["kernel_debian"].name), "sha256": KERNEL_SOURCES["kernel_debian"].sha256}),
        json.encode({"op": "patch_series", "series": "debian/patches/series", "format": "gnu"}),
    ]
    prepared_source(name = "kernel_debian_prepared", steps = steps,
                    gnu_tools = "@kernel_patch_tools//:ROOT", build_file = Label("//tools/bazel:prepared.BUILD.bazel"))
    patch_names = []
    for line in module_ctx.read(Label("//:patches-sonic/series")).splitlines():
        line = line.partition("#")[0].strip()
        if line:
            patch_names.append("patches-sonic/" + line)
    inputs = {name: Label("//:" + name) for name in patch_names}
    for name in patch_names:
        steps.append(json.encode({"op": "patch", "input": name, "format": "gnu"}))
    prepared_source(name = "kernel_prepared", steps = steps, inputs = inputs,
                    gnu_tools = "@kernel_patch_tools//:ROOT", build_file = Label("//tools/bazel:prepared.BUILD.bazel"))

kernel_sources = module_extension(implementation = _kernel_sources_impl)
