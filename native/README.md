# Native kernel interfaces for the VS installer

The buildimage root module selects this directory with a Bzlmod local path
override at its kernel gitlink. The runtime and control tars, boot files,
metadata, external-module interface and five Debian packages are the native
interfaces previously published in sonic-linux-kernel 0.0.4 for Linux 6.12.41.
The links to the kernel recipe, configurations and patch series keep them
declared as Bazel inputs from the same checkout.

The top-level module continues to provide the standalone native and cross
package targets, including ARMHF, on the matching Debian kernel release.
