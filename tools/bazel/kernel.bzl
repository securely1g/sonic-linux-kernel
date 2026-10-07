"""Cacheable Debian kernel compilation in the pinned shared build worker."""

load("@sonic_build_infra//tools/build_tools:defs.bzl", "PythonRuntimeInfo")
load(":sources.bzl", "KERNEL_SOURCES")

_PACKAGES = [
    "linux-headers-6.12.41+deb13-common-sonic_6.12.41-1_all.deb",
    "linux-headers-6.12.41+deb13-sonic-amd64_6.12.41-1_amd64.deb",
    "linux-image-6.12.41+deb13-sonic-amd64-unsigned_6.12.41-1_amd64.deb",
    "linux-kbuild-6.12.41+deb13_6.12.41-1_amd64.deb",
]

def _kernel_packages_impl(ctx):
    python = ctx.attr._python[PythonRuntimeInfo]
    outputs = [ctx.actions.declare_file(name) for name in _PACKAGES]
    manifest = ctx.actions.declare_file("kernel-packages.json")
    config = ctx.actions.declare_file(ctx.label.name + ".action.json")
    source_root = ctx.file.makefile.dirname + "/" if ctx.file.makefile.dirname else ""
    sources = []
    for src in ctx.files.srcs:
        if not src.path.startswith(source_root):
            fail("kernel inputs must belong to the kernel source directory")
        sources.append({"path": src.path, "name": src.path[len(source_root):]})
    archives = []
    for name, src in [("kernel_dsc", ctx.file.dsc), ("kernel_orig", ctx.file.orig), ("kernel_debian", ctx.file.debian)]:
        source = KERNEL_SOURCES[name]
        archives.append({"path": src.path, "name": source.name, "sha256": source.sha256})
    ctx.actions.write(config, json.encode({
        "schema": 1,
        "sources": sources,
        "archives": archives,
        "build_tools": ctx.file.build_tools.path,
        "outputs": [f.path for f in outputs],
        "manifest": manifest.path,
    }))
    ctx.actions.run(
        executable = python.interpreter,
        arguments = [ctx.file._runner.path, config.path],
        inputs = depset(ctx.files.srcs + [config, ctx.file.build_tools, ctx.file.dsc, ctx.file.orig, ctx.file.debian]),
        tools = depset([python.interpreter, ctx.file._runner], transitive = [python.files]),
        outputs = outputs + [manifest],
        env = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "PYTHONHASHSEED": "0",
        },
        mnemonic = "SonicKernelBuild",
        progress_message = "Compiling SONiC 6.12.41 AMD64 VS kernel packages",
        execution_requirements = {"block-network": "", "no-remote-exec": "1"},
    )
    return [DefaultInfo(files = depset(outputs + [manifest]))]

kernel_packages = rule(
    implementation = _kernel_packages_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True, mandatory = True),
        "makefile": attr.label(allow_single_file = True, mandatory = True),
        "dsc": attr.label(allow_single_file = True, mandatory = True),
        "orig": attr.label(allow_single_file = True, mandatory = True),
        "debian": attr.label(allow_single_file = True, mandatory = True),
        "build_tools": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
        "_runner": attr.label(default = Label("//tools/bazel:kernel_action.py"), allow_single_file = True, cfg = "exec"),
        "_python": attr.label(default = Label("//tools/bazel:python_runtime"), providers = [PythonRuntimeInfo], cfg = "exec"),
    },
)
