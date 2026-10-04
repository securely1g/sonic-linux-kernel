# Cached kernel source builds

`//:kernel_packages` compiles the existing SONiC kernel source and creates the
four native Debian packages needed by buildimage: the unsigned image, common
headers, AMD64 headers, and kbuild. The initial supported configuration is
Debian Trixie, AMD64 execution and target, VS, kernel `6.12.41-1` with ABI
`6.12.41+deb13-sonic-amd64`. Other architectures, external patches, signing and
separate debug-package delivery remain on the existing Make path.

Bazel declares the original Debian source archives, all SONiC patches and
configuration, the Make recipe, the action program, and the complete shared
`sonic-build-infra` kernel tool runtime as inputs. Repository fetching verifies
archive SHA-256 hashes before the action starts. The action copies the declared
tools into private scratch space and runs the existing Make/Kbuild packaging
process inside a chroot with a fixed `/build` path, locale and source timestamp.
It makes no source downloads during compilation. Changing any declared input
invalidates the kernel action; changing SWSS source does not.

The existing Debian recipe generates a temporary module-signing key and removes
its private key after installation. This migration preserves that behavior, so
independent cold builds are not claimed to be byte-for-byte reproducible. A
cache hit returns the exact packages produced by the trusted cache writer.

The action writes the four DEBs and `kernel-packages.json`. The manifest records
their control metadata, sizes and hashes, the Debian source hashes, SONiC input
identity and declared build-tool identity. It does not claim that cached packages
were freshly compiled by the consumer. The default Make path is unchanged;
`KERNEL_SOURCE_DIR` selects supplied source archives. Debian's normal build
dependency check runs against the declared runtime's package status database;
the generated SONiC control file and selected build profiles remain in effect.

## Registry selection

Local builds and normal CI use `sonic-bazel-registry/main`, with Bazel Central
Registry for third-party modules. Dependency versions and source checksums stay
pinned in the module definitions and registry entries.

This Draft PR still needs the kernel tools registration in
[registry #39](https://github.com/securely1g/sonic-bazel-registry/pull/39). Until
that version lands, `main` cannot resolve it. The source/cache CI job explicitly
replaces the single SONiC endpoint in its checked-out cache-consumer workspace
with `codex/kernel-build-tools-current` for review. It does not add a fallback registry.
For local validation of this Draft PR, explicitly change only the SONiC URL in
`tools/bazel/cache-consumer/.bazelrc` to that branch as well. If building the
repository root instead, select it in the root `.bazelrc`.

After the registration lands, remove the workflow's temporary registry override
and selection step, and restore any local override to `main`. Buildimage's
Draft kernel integration selects its own pending registration branch explicitly;
both workspaces use `main` by default.

## Run locally

The launcher needs Linux AMD64 and Docker. It runs as root **inside a disposable
container** because unpacked Debian build tools use a chroot; it needs Docker's
normal `SYS_CHROOT` and `MKNOD` capabilities, without privileged mode or a mounted
Docker socket. The pinned Debian worker supplies Bazel's bootstrap runtime.
The launcher installs `xz-utils` in that disposable worker to decompress fetched
APT indexes before Bazel constructs the declared tool runtime. APT verifies its
repository signatures, and Bazel verifies the fetched package/source hashes.
The compiler, Make and packaging tools come from Bazel's declared tool tree.
The worker network remains available for Bazel's repository fetching and remote
cache connection. The kernel process uses a filesystem chroot and supplied
archives; this launcher does not claim to enforce a separate network namespace
for that process. `SonicKernelBuild` uses local execution inside this worker so
its normal chroot and device-node capabilities remain available.

```sh
python3 tools/bazel/build.py \
  --workspace tools/bazel/cache-consumer \
  --work-dir /tmp/my-kernel-build \
  --module-override "sonic-linux-kernel=$PWD" \
  --remote-cache http://127.0.0.1:8080 \
  --bazel-arg=--strategy=SonicKernelBuild=local
```

Use the external-consumer graph for both cache producers and buildimage consumers.
Building this repository as the Bazel root uses different repository paths and
does not establish cross-repository cache reuse. Keep the dependency versions and
target configuration in `cache-consumer/MODULE.bazel` aligned with buildimage's
`tools/bazel/kernel/MODULE.bazel`.

The remote cache URL is configurable and has no default service. CI starts an
empty loopback cache to verify the protocol. A persistent shared service can use
the same `--remote-cache` option; consumers can add `--remote-cache-read-only`.
A miss compiles the kernel from source. Only trusted builders should have write
access to a shared cache. Credentials must not appear in the URL or recorded
invocation; deploy authentication through the surrounding build environment.

Without a service, omit `--remote-cache` and optionally set `--disk-cache` to a
dedicated persistent directory. `--repository-cache` reuses source downloads;
it does not supply compiled kernel outputs. `--distdir` can supply previously
downloaded raw source archives, which Bazel still checks against their hashes.
Optional public CA bundles and JVM trust stores affect repository fetching only.

Compilation is initially one coarse Bazel action. A hit skips all kernel
compilation; a kernel input change runs the full existing kernel build. This
target supports remote **caching**, with local execution in the disposable
worker; it does not offer remote execution of privileged chroot operations.

## Verify a cache hit

Start with an empty remote cache, build once, and run the same target in a second
`--work-dir` with `--remote-cache-read-only`. Do not enable a disk cache for this
test. Then run:

```sh
python3 tools/bazel/verify_cache.py \
  --cold /tmp/my-kernel-build --hit /tmp/my-kernel-cache-hit \
  --artifacts /tmp/my-kernel-evidence
```

The check requires the cold action to execute and the second action's Bazel
execution record to report `remote cache hit`. It compares declared action
inputs and all output hashes, and retains the packages and a JSON receipt.
Elapsed time alone, unchanged files, or replayed compiler log text do not prove
that compilation was skipped. The PR workflow runs this check against a fresh
local cache and retains its execution logs, profile and generated module lock.
