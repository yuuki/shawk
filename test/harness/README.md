# Test environments

The environments the tests need beyond Go, each brought up and torn down by
one command, on macOS and on Linux:

| environment | up | down | for |
|---|---|---|---|
| disposable PostgreSQL 16 on the host | `make pg-up` | `make pg-down` | the tests of the connector, the end-to-end test |
| a Linux kernel in QEMU, per test run | `make vm-test` | (ends with the run) | the tests that load the BPF programs on other kernels |
| a Slurm cluster in a VM of Lima | `make slurm-up` | `make slurm-down` | jobs of Slurm (#173 cgroups, #174 srun ports), MPI, root tests on Rocky Linux 9 |

Everything they start belongs to the workspace, the checkout or worktree
they are run from: the state is in `build/harness/`, the port of PostgreSQL
and the name of the VM derive from the path of the workspace, so that
worktrees and agent sessions running at the same time on one host do not
clash. Running `up` again is harmless.

Downloads are pinned by version and SHA-256 and cached in `build/cache/`, or
in `SHAWK_CACHE_DIR`, which several workspaces can share (e.g.
`SHAWK_CACHE_DIR=~/.cache/shawk`). The packages of Rocky Linux in the VM are
the exception: dnf checks their signatures, but takes the current ones and
does not cache them. Nothing secret is committed: the password of
PostgreSQL and the munge key are made where they are used. `make clean`
keeps `build/harness`, which environments still running use (the VM
mounts it too); `make pg-down` and `make slurm-down` delete it. The
commands that change an environment wait for one another in a workspace.

## PostgreSQL

```bash
make pg-up                                  # start, and print the DSNs
eval "$(test/harness/postgres.sh env)"      # export them in this shell
make pg-test                                # the tests of the connector with it
test/harness/postgres.sh run make test      # any command with the DSNs (make test needs Linux)
make pg-down                                # stop it and delete its data
```

[`postgres.sh`](postgres.sh) runs the relocatable build of PostgreSQL 16 of
[zonky embedded-postgres-binaries](https://github.com/zonkyio/embedded-postgres-binaries)
(Maven Central, darwin and linux, amd64 and arm64) as the user, without
root, containers or a VM, on 127.0.0.1 and a port of the workspace. The
superuser `postgres` has a random password, in the DSNs and in
`build/harness/postgres/password`, since other users of the host and its
VMs reach its loopback. It has no `psql`: `make e2e` needs one from the
system. initdb refuses to run as root.

## BPF tests in a VM

```bash
make vm-test KERNEL=rocky9 ARCH=aarch64     # rocky9, 5.14, 5.15 on x86_64 or aarch64
```

[`test/vm/run.sh`](../vm/run.sh) boots the kernel with an initramfs of the
test binaries; each run has its own temporary directory and no network, so
runs do not clash. It uses KVM on Linux and HVF on macOS when the guest has
the architecture of the host, and emulates it otherwise (slow). Without
`rpm2cpio` or `dpkg-deb`, as on macOS, `bsdtar` extracts the kernel packages.
On macOS, Homebrew has `qemu`, `xz` and `coreutils` (`timeout`).

## Slurm cluster

```bash
make slurm-up                                         # Slurm 26.05.5, cgroups of jobs named by SLUID
make slurm-up SLURM_CGROUP_JOB_ID_PATHS=yes           # reconfigure: job_<id>, as before 26.05
make slurm-up SLURM_VERSION=24.11.7 SLURM_SRUN_PORT_RANGE=60001-63000
make slurm-check                                      # run jobs and check them (below)
test/harness/slurm.sh run srun -n2 hostname           # any command, as root, in the VM
test/harness/slurm.sh shell                           # a shell, as the user
make slurm-down                                       # delete the VM
```

[`slurm.sh`](slurm.sh) creates a VM of Lima named `shawk-slurm-<workspace>`
from the pinned image of Rocky Linux 9.8 (4 CPUs, 6 GiB; `SHAWK_VM_CPUS`,
`SHAWK_VM_MEMORY`, `SHAWK_VM_DISK`), which mounts the workspace at the same
path and forwards no port to the host. [`slurm/provision.sh`](slurm/provision.sh)
builds Slurm from its source (checked against the SHA-256 of SchedMD) into
`/opt/slurm`, once per version and kept in the cache, and runs slurmctld,
slurmd and munge on the VM, a cluster of one node with cgroup v2:

| variable | slurm.conf, cgroup.conf | default |
|---|---|---|
| `SLURM_VERSION` | 22.05.11, 23.02.8, 23.11.11, 24.05.8, 24.11.7, 25.05.9, 25.11.8 or 26.05.5 | 26.05.5 |
| `SLURM_CGROUP_JOB_ID_PATHS` | `CgroupJobIdPaths` (26.05 and later): `no` names the cgroup of a job after its SLUID, `yes` `job_<id>` | Slurm's (`no`) |
| `SLURM_SRUN_PORT_RANGE` | `SrunPortRange`, e.g. `60001-63000` | none |
| `SLURM_MPI` | `yes`: PMIx, Open MPI 4.1 of Rocky Linux, `MpiDefault=pmix` | `yes` |
| `SLURM_JOBACCT` | `JobAcctGatherType`: `cgroup`, `linux` or `none` | `cgroup` |
| `SLURM_CONSTRAIN_RAM` | `ConstrainRAMSpace` | `no` |
| `SLURM_CPU_SPEC` | `CpuSpecList` | none |

Running `up` again with other values reconfigures the cluster; another
version replaces Slurm and deletes the state of slurmctld.
[`slurm/check.sh`](slurm/check.sh) (`make slurm-check`) runs a batch job of
the user with an srun of two tasks and checks with
[`units`](units/main.go), which applies the agent's `procinfo.Unit` to the
cgroups of the processes, that each has the unit its step in Slurm calls
for (`slurm/batch` for the script and srun, `slurm/step` for the tasks,
`slurmstepd`), that the cgroup of the job is `job_<id>` or the SLUID that
scontrol shows, as the version and `CgroupJobIdPaths` have it, and that
srun listens in `SrunPortRange`; then that an MPI program runs with two
ranks through srun.

The VM is also a Linux host with systemd for the tests that need one. It
has the Go of `go.mod` (1.27.3, the release of go.dev pinned by its SHA-256,
with `GOTOOLCHAIN=local`), `make`, `psql` and the tools of `make e2e`, and
its own state of `test/harness` (`/var/tmp/shawk-harness`), so the
PostgreSQL of `postgres.sh` runs in it beside that of the host:

```bash
test/harness/slurm.sh shell test/harness/postgres.sh up              # as the user of the VM
test/harness/slurm.sh shell test/harness/postgres.sh run make test   # all of make test, on Linux
test/harness/slurm.sh run make test-root                             # the BPF tests, as root
```

`make e2e` also needs SELinux permissive in the VM
(`test/harness/slurm.sh run setenforce 0`): `ip netns exec` cannot mount
`/sys` under the policy of Rocky Linux.

Lima comes from Homebrew on macOS (`vz`). On Linux, `slurm.sh` downloads
the pinned release of Lima if `limactl` is missing, and needs QEMU and
`/dev/kvm` (see the job `kernels` of `.github/workflows/test.yml`).

## Variables of the tests

| variable | read by | set by |
|---|---|---|
| `SHAWK_TEST_POSTGRES_DSN` | the `TestPG*` tests of `collector/shawkconnector` (`make test`, `make pg-test`); skipped without it | `postgres.sh env`, `run` |
| `SHAWK_E2E_POSTGRES_DSN` | `test/e2e/run.sh` (`make e2e`), which drops and recreates its schemas | `postgres.sh env`, `run` (database `shawke2e`) |
| `SHAWK_TEST_STRICT` | the BPF tests (`make test-root`, `vm-test`, `e2e`): a skip fails | `test/vm/run.sh` (1 unless set) |
| `SHAWK_TEST_NO_UDP`, `SHAWK_TEST_NO_NFS`, `SHAWK_TEST_NO_CONNTRACK` | the BPF tests: what the kernel lacks | `test/vm/run.sh` from the kernel |
| `SHAWK_TARGET_BTF`, `SHAWK_TARGET_MODULE_BTF`, `SHAWK_FRESH_OBJECT` | `TestKernelCompatibility` and the check of the committed object | `make compat`, `make check-object` |
| `VM_TEST_ARGS`, `VM_TIMEOUT` | `test/vm/run.sh`: arguments of the test binaries, a deadline | the user |
| `SLURM_*`, `SHAWK_VM_*` | `slurm.sh up` (above) | the user |
| `SHAWK_CACHE_DIR`, `SHAWK_HARNESS_ID` | all of `test/harness`: the cache, the name of the workspace (8 hex digits of its path) | the user |

## In the sandbox of an agent

Agents such as Claude Code run commands in a sandbox (Seatbelt on macOS)
that denies what Lima and PostgreSQL need: Lima reads sysctls and writes
`~/.lima`, and PostgreSQL makes System V shared memory. Run `postgres.sh`
and `slurm.sh` outside the sandbox. Root in the VM needs no `sudo` on the
host: `slurm.sh run` runs the command as root inside the VM.

## Other users of the cluster

A script that needs a cluster of Slurm, such as `test/nodeload` of #195,
can have it made by `slurm.sh up` (`SLURM_JOBACCT`, `SLURM_CONSTRAIN_RAM` and
`SLURM_CPU_SPEC` are the `ACCT`, `RAM` and `SPEC` of
`test/nodeload/slurm.sh`) and run in the VM with `slurm.sh run`. To change
the settings from inside the VM, between measurements, it runs
`slurm/provision.sh` without `VERSION`, which reconfigures the Slurm
installed:

```bash
JOBACCT=cgroup CONSTRAIN_RAM=yes bash test/harness/slurm/provision.sh   # as root in the VM
```
