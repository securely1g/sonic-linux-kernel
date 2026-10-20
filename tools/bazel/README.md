# Cached kernel source builds

`//:kernel_artifacts` compiles the maintained SONiC/Debian kernel and exports
three filesystem layers with one provenance manifest:

| Target | Artifact | Installed content |
| --- | --- | --- |
| `//:runtime_tar` | `kernel-runtime.tar` | `/boot/vmlinuz-*`, config, real System.map, and signed modules under `/usr/lib/modules/<ABI>` |
| `//:debug_tar` | `kernel-debug.tar` | Matching unstripped vmlinux/modules, GNU build-ID links, patched sources and generated headers |
| `//:development_tar` | `kernel-development.tar` | Configured common/native headers, Module.symvers, BTF, kbuild programs, and relative build/source links |
| `//:manifest` | `kernel-artifacts.json` | Schema 2: source/tool identities, TAR kinds/hashes/sizes, and verified debug pairing |

Supported configurations are Debian Trixie, native AMD64 or native ARM64 execution
and target, VS, kernel `6.12.41-1`, and an unsigned boot image. The ABI is
`6.12.41+deb13-sonic-amd64` or `6.12.41+deb13-sonic-arm64`.
`kernel_artifacts` selects the matching native target; output directories include
the architecture while preserving the TAR basenames.
Cross-compilation, other architectures, external patches and secure-upgrade signing
remain on the existing Make path.

## Source, configuration and installation

Bazel declares the checksum-verified Debian source archives, SONiC patches and
configuration, source preparation/staging programs, and the complete shared
`sonic-build-infra` execution tool runtime. The action copies these tools into
private scratch space and runs inside a chroot at a fixed `/build` path with a
fixed locale and source timestamp. Compilation makes no source downloads.

Source extraction still uses `dpkg-source`, then the SONiC config/patch overlay,
`manage-config`, and Debian's generated rules. Only
`build-arch_<arch>_sonic_<arch>_image` and `build-arch_<arch>_kbuild` are selected,
where `<arch>` is `amd64` or `arm64`.
Debian's `build_image` already stages the boot image, stripped signed modules,
and original unsigned debug ELFs. `stage-kernel.mk` reuses Debian's kbuild
**install** recipes; `stage_kernel.py` preserves Debian's configured header
layout and writes the three TARs using the declared GNU tar.

The Bazel path never invokes `dpkg-buildpackage`, binary-package targets,
`dh_builddeb`, or DEB assembly. It fails if a binary Debian package appears in
the private source output. Fetched Debian build-tool packages are declared
execution inputs; this does not turn the kernel into a prebuilt runtime.
The standalone Make DEB path remains available for configurations outside this
migration.

Runtime and development layers retain the Debian source copyright/changelog.
Development headers include `.config`, `.kernel*`, Module.symvers, generated
includes, BTF-only vmlinux, module.lds, and installed kbuild scripts/tools. The
relative `/usr/lib/modules/<ABI>/{build,source}` links are in the development
layer; runtime/debug archives contain no links into the disposable build tree.

## Debug symbols and sources

Debian builds with its existing optimized configuration and
`CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y`. The action requires DWARF in the
original vmlinux and every debug module, compares every GNU build ID to its
stripped runtime counterpart, and checks that runtime module signatures remain
intact. On AMD64 it extracts the ELF embedded in the boot image and compares its
build ID with the packaged vmlinux. ARM64 boots a raw `Image`; the check recreates
that image from the same debug vmlinux using the pinned Kbuild objcopy recipe and
requires identical bytes.

Do not add a `.gnu_debuglink` after signing a module: changing its bytes would
invalidate the signature. The debug TAR instead supplies matching GNU build-ID
links and conventional `/usr/lib/debug` locations. It also ships the patched
kernel source and generated headers under `/usr/src/debug/linux-<ABI>`, retaining
the relative Debian build layout recorded by `-fdebug-prefix-map`.

CI extracts only the runtime/debug TARs into a new root and runs:

```sh
python3 tools/bazel/verify_debug.py --architecture amd64 --root /installed --output debugger.json
```

This check requires GDB to load the packaged build-ID symbols, resolve actual
shipped source lines for `start_kernel` and a representative module, and inspect
`struct task_struct`. The compiler tree is unavailable. GDB runs in a separate
native validation container; its version and architecture are recorded in the
public validation summary. Use `--architecture arm64` for ARM64 artifacts.
For ARM64 kernel symbol lookup, the verifier uses a stripped ELF probe derived
from the vmlinux that matched the raw boot image; that probe is not a deployed
boot artifact. Module lookup uses the actual runtime module on both architectures.

The Debian build generates a temporary module-signing key and removes its
private key after installation. Independent cold builds are therefore not
claimed to be byte-identical. A cache hit returns the exact TARs from its trusted
producer.

## Buildimage handoff

A TAR is an installed filesystem payload, with no package-manager records or
maintainer scripts. Consumers must explicitly run `depmod`, create/update the
ABI-specific initramfs after SONiC hooks, and install development tools before
building out-of-tree modules. The debug TAR belongs in the debug image/layer.
No adapter should fabricate dpkg state or convert these TARs back into DEBs.

Compilation remains one coarse Bazel action. An unchanged action can reuse all
three layers; a source/config/tool change rebuilds the kernel. Selecting only
one output layer still executes that same kernel action on a miss. This supports
remote **caching** with local execution, not remote execution of the chroot.

## Registry selection

Local builds and normal CI use `sonic-bazel-registry/main` plus Bazel Central
Registry. This Draft PR still needs the kernel execution tools in
[registry #39](https://github.com/securely1g/sonic-bazel-registry/pull/39).
Its ARM64 tool runtime includes the ARM32 compatibility-vDSO compiler from
[build-infra #52](https://github.com/securely1g/sonic-build-infra/pull/52).
Until that entry lands, source/cache CI explicitly replaces the single SONiC
endpoint in private consumer copies with `codex/kernel-build-tools-current`.
It does not add a fallback registry or pin a registry commit. Local review builds
must select that branch in their private consumer `.bazelrc` as well. Remove the
temporary override when the exact dependency lands on main.

## Run locally and verify cache reuse

The launcher needs native Linux AMD64 or ARM64 and Docker. It selects the matching
checksum-pinned Bazel binary, Docker image platform and Bazel execution/target
platforms. `--architecture amd64` or `--architecture arm64` can assert the native
host architecture; a mismatched host is rejected. Root runs only inside its disposable
pinned Debian container, with Docker's normal `SYS_CHROOT`/`MKNOD` capabilities;
there is no privileged mode or mounted Docker socket. The launcher installs
`xz-utils` only to bootstrap APT repository-index decompression. Kernel compiler,
Make, archive and installation tools come from the declared runtime. The worker
network permits repository fetching/cache traffic; the chroot uses supplied
archives but is not a separate network namespace.

```sh
python3 tools/bazel/build.py \
  --workspace tools/bazel/cache-consumer \
  --work-dir /tmp/my-kernel-build \
  --module-override "sonic-linux-kernel=$PWD" \
  --target @sonic_linux_kernel//:kernel_artifacts \
  --remote-cache http://127.0.0.1:8080
```

The same launcher command works on either native architecture. Direct Bazel
commands on an ARM64 host use `--config=arm64` with the root `.bazelrc`; the
default direct-Bazel configuration remains AMD64.

The own-source override validates the proposed component. Buildimage's registered
consumer selects the published source snapshot; rerun that graph after source
and registry updates. Keep dependency versions aligned between consumers.

To prove remote reuse, build with an empty trusted remote cache, then use a
second private consumer and fresh `--work-dir`, `--remote-cache-read-only`, and
no disk cache. Run:

```sh
python3 tools/bazel/verify_cache.py \
  --architecture amd64 \
  --cold /tmp/my-kernel-build --hit /tmp/my-kernel-cache-hit \
  --artifacts /tmp/my-kernel-evidence
```

The verifier requires real cold execution and a `remote cache hit` for the
second kernel action, identical declared action inputs, and identical hashes
for all three TARs and the manifest. Timing alone does not establish a hit.
Use `--architecture arm64` for ARM64 verification. Invocations, manifest ABI,
tool identity, TAR layout and debugger results must match the expected architecture.
Without a remote service, omit that option; `--repository-cache` only reuses
verified downloads, while an optional `--disk-cache` stores local action results.
Never put credentials in the recorded remote-cache URL.

## CI evidence

The matrix uses `ubuntu-24.04` for AMD64 and native `ubuntu-24.04-arm` for ARM64.
Each job checks its native machine/userspace architecture, compiles into an empty
remote cache, and verifies a fresh read-only consumer with its disk cache disabled.
Checks and artifact names distinguish the two architectures.

Source/cache CI retains three verified TARs, `kernel-artifacts.json`,
`validation.json`, and `resolution.json`. The collector validates the complete
manifest, source/tool identity, safe filesystem TAR contents, matching module
inventories, GDB results, and producer/cache-consumer hashes before publication.
Source inputs and registry/module resolution must agree between both builds.

Raw logs, execution records, BEP, profiles, generated locks, cache diagnostics
and arbitrary environment values remain in private job scratch. The public
resolution summary is an allowlisted module/registry record, not a reusable
lockfile. On an earlier failure, only a bounded status summary is published.
The focused Python tests use harmless TAR fixtures and do not create DEBs.
