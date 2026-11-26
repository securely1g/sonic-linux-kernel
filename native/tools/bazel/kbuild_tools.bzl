"""Native source builds of the programs installed by Debian's linux-kbuild.

The source membership and four modpost/two objtool variants follow the fixed
Linux source's debian/rules.d. All compilation is owned by the target C toolchain.
"""

load("@rules_cc//cc:defs.bzl", "CcInfo", "cc_binary", "cc_common", "cc_library")
load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_python//python:py_binary.bzl", "py_binary")
load("@sonic_build_infra//binary:strip_binary.bzl", "strip_binary")

KBUILD_TOOLS = {
    "extract_cert": "certs/extract-cert",
    "kallsyms": "scripts/kallsyms",
    "recordmcount": "scripts/recordmcount",
    "sign_file": "scripts/sign-file",
    "unifdef": "scripts/unifdef",
    "fixdep": "scripts/basic/fixdep",
    "genksyms": "scripts/genksyms/genksyms",
    "conf": "scripts/kconfig/conf",
    "modpost": "scripts/mod/modpost",
    "modpost_lsb_32": "scripts/mod/modpost.real-lsb-32",
    "modpost_lsb_64": "scripts/mod/modpost.real-lsb-64",
    "modpost_msb_32": "scripts/mod/modpost.real-msb-32",
    "modpost_msb_64": "scripts/mod/modpost.real-msb-64",
    "objtool": "tools/objtool/objtool",
    "objtool_powerpc": "tools/objtool/objtool.real-powerpc",
    "objtool_x86": "tools/objtool/objtool.real-x86",
    "resolve_btfids": "tools/bpf/resolve_btfids/resolve_btfids",
}

_SRC = Label("@kernel_prepared//:Makefile").workspace_root
_REPO = Label("//:BUILD.bazel").workspace_root
_DEBIAN = Label("@kernel_debian_prepared//:Makefile").workspace_root + "/debian/rules.d"
_CRYPTO = Label("@build_tools//libssl-dev:libcrypto_cc")
_ELF = Label("@build_tools//libelf-dev:libelf_cc")
_ZLIB = Label("@build_tools//zlib1g-dev:libz_cc")

# These are source include directories from the original component, not library
# dependency include paths. Header filegroups declare their complete inputs.
_SCRIPT_INCLUDES = ["-I" + _SRC + "/scripts/include"]
_TOOL_INCLUDES = ["-I" + _SRC + "/" + p for p in ["tools/include", "tools/include/uapi", "tools/lib"]]
_TARGET_UAPI = select({
    "@platforms//cpu:x86_64": ["-I" + _SRC + "/tools/arch/x86/include/uapi"],
    "@platforms//cpu:aarch64": ["-I" + _SRC + "/tools/arch/arm64/include/uapi"],
})
_LIBBPF_ARCH_INCLUDES = select({
    "@platforms//cpu:x86_64": ["-I" + _SRC + "/tools/arch/x86/include"],
    "@platforms//cpu:aarch64": ["-I" + _SRC + "/tools/arch/arm64/include"],
})
_COPTS = ["-O2", "-g", "-Wall", "-Wformat", "-Werror=format-security", "-fstack-protector-strong"]


def _offsets_impl(ctx):
    cc = find_cc_toolchain(ctx)
    feature_config = cc_common.configure_features(ctx = ctx, cc_toolchain = cc, requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    variables = cc_common.create_compile_variables(feature_configuration = feature_config, cc_toolchain = cc)
    flags = cc_common.get_memory_inefficient_command_line(feature_configuration = feature_config, action_name = ACTION_NAMES.c_compile, variables = variables)
    out = ctx.actions.declare_file(ctx.label.name + ".s")
    args = ctx.actions.args()
    args.add_all(flags)
    args.add_all(["-S", "-nostdinc", "-O2", "-I" + _SRC + "/include", "-include", ctx.file.types.path])
    args.add(ctx.file.src)
    args.add_all(["-o", out.path])
    headers = depset(transitive = [dep[CcInfo].compilation_context.headers for dep in ctx.attr.deps])
    ctx.actions.run(
        executable = cc_common.get_tool_for_action(feature_configuration = feature_config, action_name = ACTION_NAMES.c_compile),
        arguments = [args],
        inputs = depset([ctx.file.src, ctx.file.types], transitive = [cc.all_files, headers]),
        outputs = [out],
        mnemonic = "KernelDeviceTableOffsets",
    )
    return [DefaultInfo(files = depset([out]))]

_offsets = rule(
    implementation = _offsets_impl,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "types": attr.label(allow_single_file = True, mandatory = True),
        "deps": attr.label_list(providers = [CcInfo]),
    },
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)


def _source(path):
    return Label("@kernel_prepared//:" + path)


def _debian(path):
    return Label("@kernel_debian_prepared//:debian/rules.d/" + path)


def _binary(name, suffix, headers, common, srcs, copts = [], deps = [], defines = []):
    raw = name + "_" + suffix + "_unstripped"
    cc_binary(
        name = raw,
        srcs = srcs,
        copts = _COPTS + copts,
        local_defines = defines,
        deps = [":" + headers] + deps,
        linkstatic = False,
        linkopts = ["-Wl,-z,relro", "-Wl,-z,now"],
        **common
    )
    split = name + "_" + suffix + "_split"
    strip_binary(name = split, src = ":" + raw, **common)
    native.filegroup(name = name + "_" + suffix, srcs = [":" + split], output_group = "stripped", **common)


def kernel_kbuild_tools(name, **kwargs):
    """Produce each KBUILD_TOOLS suffix as name + '_' + suffix."""
    common = {k: kwargs[k] for k in ["target_compatible_with", "visibility", "tags"] if k in kwargs}
    exec_common = {k: kwargs[k] for k in ["visibility", "tags"] if k in kwargs}
    generator = name + "_generate"
    py_binary(name = generator, srcs = [Label("//tools/bazel:kbuild_generate.py")], main = "kbuild_generate.py", **exec_common)
    headers = name + "_headers"
    cc_library(
        name = headers,
        hdrs = [Label("@kernel_prepared//:tool_headers"), Label("@kernel_debian_prepared//:kbuild_headers")] + select({
            # tools/include/uapi/asm/bpf_perf_event.h includes this source
            # through its relative ../../arch/arm64 path on AArch64.
            "@platforms//cpu:aarch64": [_source("arch/arm64/include/uapi/asm/bpf_perf_event.h")],
            "//conditions:default": [],
        }),
        textual_hdrs = [_source(p) for p in ["scripts/genksyms/keywords.c", "tools/arch/x86/lib/inat.c", "tools/arch/x86/lib/insn.c"]],
        **common
    )


    simple = {
        "extract_cert": ("certs/extract-cert.c", [_CRYPTO]),
        "kallsyms": ("scripts/kallsyms.c", []),
        "recordmcount": ("scripts/recordmcount.c", []),
        "sign_file": ("scripts/sign-file.c", [_CRYPTO]),
        "unifdef": ("scripts/unifdef.c", []),
        "fixdep": ("scripts/basic/fixdep.c", []),
    }
    for suffix, (src, deps) in simple.items():
        _binary(name, suffix, headers, common, [_source(src)], copts = _SCRIPT_INCLUDES + ["-I" + _SRC + "/scripts"], deps = deps, defines = ["_LARGEFILE64_SOURCE", "_FILE_OFFSET_BITS=64"] if suffix in ["extract_cert", "sign_file", "kallsyms", "recordmcount", "unifdef"] else [])

    # Each grammar/parser is an explicit generator action. Bison emits both
    # outputs together, so its header and parser cannot race or drift.
    for directory, grammar, lexer in [("genksyms", "parse", "lex"), ("kconfig", "parser", "lexer")]:
        generated = name + "/" + directory
        grammar_c = generated + "/" + grammar + ".tab.c"
        grammar_h = generated + "/" + grammar + ".tab.h"
        lexer_c = generated + "/" + lexer + ".lex.c"
        native.genrule(
            name = name + "_" + directory + "_parser",
            srcs = [_source("scripts/" + directory + "/" + grammar + ".y")],
            outs = [grammar_c, grammar_h],
            tools = ["@sonic_build_infra//tools/build_tools:bison", "@sonic_build_infra//tools/build_tools:m4"],
            cmd = "M4=$(location @sonic_build_infra//tools/build_tools:m4) $(location @sonic_build_infra//tools/build_tools:bison) -t -l --defines=$(location " + grammar_h + ") -o $(location " + grammar_c + ") $<",
            **exec_common
        )
        native.genrule(
            name = name + "_" + directory + "_lexer",
            srcs = [_source("scripts/" + directory + "/" + lexer + ".l"), grammar_h],
            outs = [lexer_c],
            tools = ["@sonic_build_infra//tools/build_tools:flex", "@sonic_build_infra//tools/build_tools:m4"],
            cmd = "M4=$(location @sonic_build_infra//tools/build_tools:m4) $(location @sonic_build_infra//tools/build_tools:flex) -L -o$@ $(location " + str(_source("scripts/" + directory + "/" + lexer + ".l")) + ")",
            **exec_common
        )
        sources = ["genksyms.c"] if directory == "genksyms" else ["conf.c", "confdata.c", "expr.c", "menu.c", "preprocess.c", "symbol.c", "util.c"]
        _binary(name, "genksyms" if directory == "genksyms" else "conf", headers, common,
               [_source("scripts/" + directory + "/" + p) for p in sources] + [grammar_c, grammar_h, lexer_c],
               copts = _SCRIPT_INCLUDES + ["-I" + _SRC + "/scripts/" + directory, "-I$(GENDIR)/" + (_REPO + "/" + native.package_name()).rstrip("/") + "/" + generated])

    native.genrule(
        name = name + "_modpost_options",
        srcs = [_source("scripts/mod/modpost.c")],
        outs = [name + "/modpost-opts.h"],
        tools = [":" + generator],
        cmd = "$(location :" + generator + ") options $@ $<",
        **exec_common
    )
    _binary(name, "modpost", headers, common, [_debian("scripts/mod/modpost.c"), name + "/modpost-opts.h"],
           copts = ["-I$(GENDIR)/" + (_REPO + "/" + native.package_name()).rstrip("/") + "/" + name])
    for endian in ["lsb", "msb"]:
        for bits in ["32", "64"]:
            variant = endian + "-" + bits
            generated = name + "/modpost/" + variant
            for header in ["types", "elfconfig"]:
                inputs = [_debian("scripts/mod/" + header + ".h"), _debian("scripts/mod/real-" + variant + "/" + header + ".h")]
                native.genrule(
                    name = name + "_" + variant + "_" + header,
                    srcs = inputs,
                    outs = [generated + "/" + header + ".h"],
                    tools = [":" + generator],
                    cmd = "$(location :" + generator + ") header $@ $(SRCS)",
                    **exec_common
                )
            offsets = name + "_" + variant + "_offsets"
            _offsets(name = offsets, src = _source("scripts/mod/devicetable-offsets.c"), types = generated + "/types.h", deps = [":" + headers], **common)
            native.genrule(
                name = offsets + "_header",
                srcs = [":" + offsets],
                outs = [generated + "/devicetable-offsets.h"],
                tools = [":" + generator],
                cmd = "$(location :" + generator + ") offsets $@ $<",
                **exec_common
            )
            _binary(name, "modpost_" + endian + "_" + bits, headers, common,
                   [_source("scripts/mod/" + p) for p in ["file2alias.c", "modpost.c", "sumversion.c", "symsearch.c"]] + [generated + "/elfconfig.h", generated + "/devicetable-offsets.h"],
                   copts = _SCRIPT_INCLUDES + ["-I$(GENDIR)/" + (_REPO + "/" + native.package_name()).rstrip("/") + "/" + generated])

    subcmd = name + "_subcmd"
    cc_library(
        name = subcmd,
        srcs = [_source("tools/lib/subcmd/" + p + ".c") for p in ["exec-cmd", "help", "pager", "parse-options", "run-command", "sigchain", "subcmd-config"]],
        deps = [":" + headers],
        copts = _COPTS + _TOOL_INCLUDES + ["-std=gnu99", "-fPIC"],
        local_defines = ["_LARGEFILE64_SOURCE", "_FILE_OFFSET_BITS=64", "_GNU_SOURCE"],
        **common
    )
    inat = name + "/objtool/x86/inat-tables.c"
    native.genrule(
        name = name + "_inat_tables",
        srcs = [_source("tools/arch/x86/tools/gen-insn-attr-x86.awk"), _source("tools/arch/x86/lib/x86-opcode-map.txt")],
        outs = [inat],
        tools = ["@sonic_build_infra//tools/build_tools:gawk"],
        cmd = "$(location @sonic_build_infra//tools/build_tools:gawk) -f $(location " + str(_source("tools/arch/x86/tools/gen-insn-attr-x86.awk")) + ") $(location " + str(_source("tools/arch/x86/lib/x86-opcode-map.txt")) + ") > $@",
        **exec_common
    )
    cc_library(name = name + "_inat_header", textual_hdrs = [inat], **common)
    _binary(name, "objtool", headers, common, [_debian("tools/objtool/objtool.c")])
    common_objtool = ["weak", "check", "special", "builtin-check", "elf", "objtool"]
    common_lib = ["string", "ctype", "str_error_r", "rbtree"]
    for arch in ["x86", "powerpc"]:
        arch_objects = ["special", "decode", "orc"] if arch == "x86" else ["decode", "special"]
        srcs = [_source("tools/objtool/" + p + ".c") for p in common_objtool + (["orc_gen", "orc_dump"] if arch == "x86" else [])]
        srcs += [_source("tools/lib/" + p + ".c") for p in common_lib]
        srcs += [_source("tools/objtool/arch/" + arch + "/" + p + ".c") for p in arch_objects]
        _binary(name, "objtool_" + arch, headers, common, srcs,
               copts = _TOOL_INCLUDES + _TARGET_UAPI + ["-I" + _SRC + "/tools/arch/" + arch + "/include", "-I" + _SRC + "/tools/objtool/include", "-I" + _SRC + "/tools/objtool/arch/" + arch + "/include", "-I$(GENDIR)/" + (_REPO + "/" + native.package_name()).rstrip("/") + "/" + name + "/objtool/x86"],
               deps = [":" + subcmd, _ELF] + ([":" + name + "_inat_header"] if arch == "x86" else []))

    helper_defs = name + "/libbpf/bpf_helper_defs.h"
    native.genrule(
        name = name + "_bpf_helpers",
        srcs = [_source("scripts/bpf_doc.py"), _source("tools/include/uapi/linux/bpf.h")],
        outs = [helper_defs],
        tools = ["@sonic_build_infra//tools/build_tools:python3"],
        cmd = "$(location @sonic_build_infra//tools/build_tools:python3) $(location " + str(_source("scripts/bpf_doc.py")) + ") --header --file $(location " + str(_source("tools/include/uapi/linux/bpf.h")) + ") > $@",
        **exec_common
    )
    libbpf = name + "_libbpf"
    cc_library(
        name = libbpf,
        srcs = [_source("tools/lib/bpf/" + p + ".c") for p in ["libbpf", "bpf", "nlattr", "btf", "libbpf_errno", "str_error", "netlink", "bpf_prog_linfo", "libbpf_probes", "hashmap", "btf_dump", "ringbuf", "strset", "linker", "gen_loader", "relo_core", "usdt", "zip", "elf", "features", "btf_iter", "btf_relocate"]],
        hdrs = [helper_defs],
        deps = [":" + headers, _ELF, _ZLIB],
        copts = _COPTS + _TOOL_INCLUDES + _LIBBPF_ARCH_INCLUDES + ["-I$(GENDIR)/" + (_REPO + "/" + native.package_name()).rstrip("/") + "/" + name + "/libbpf", "-std=gnu89", "-Wno-switch-enum", "-fvisibility=hidden"],
        local_defines = ["_LARGEFILE64_SOURCE", "_FILE_OFFSET_BITS=64"],
        **common
    )
    _binary(name, "resolve_btfids", headers, common, [_source("tools/bpf/resolve_btfids/main.c")] + [_source("tools/lib/" + p + ".c") for p in ["rbtree", "zalloc", "string", "ctype", "str_error_r"]],
           copts = _TOOL_INCLUDES,
           deps = [":" + libbpf, ":" + subcmd, _ELF, _ZLIB])
