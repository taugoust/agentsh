# eBPF connect hook assets

- `connect.bpf.c`: BPF program (go:build ignore) built with clang.
- `connect_bpfel.o`: generated Linux build artifact embedded by `program_linux.go`.
- `connect_bpfel_arm64.o`: generated Linux build artifact embedded by `program_linux.go`.
- `Makefile`: helper to rebuild the objects locally.

## Rebuild

Linux Nix package builds regenerate the embedded `.o` files before `go build`, so changes to `connect.bpf.c` are picked up by `nix build` / `nixos-rebuild`. The generated `.o` files are not checked in.

For manual local rebuilds, enter the flake dev shell and run:
```bash
cd internal/netmonitor/ebpf
make clean all BPF_CLANG="$BPF_CLANG" BPF_INCLUDE="$BPF_INCLUDE"
```
Then re-run targeted tests, for example:
```bash
go test ./internal/netmonitor/ebpf -run TestPopulateAllowlistCIDR -count=1
```

## Kernel Compatibility

The eBPF programs are designed to work with Linux kernels 5.x and 6.x.

### Portability

The program uses stable `struct bpf_sock_addr` fields from kernel UAPI headers (`user_ip4`, `user_ip6`, `user_port`) and does not require a generated `vmlinux.h`. This keeps Nix builds pure: the BPF object is compiled from checked-in source plus explicit Nix inputs (`clang-unwrapped`, `libbpf`, and `linuxHeaders`), not from the running kernel's `/sys/kernel/btf/vmlinux`.

### Kernel 6.x Notes

Kernel 6.x has stricter BPF verifier rules for cgroup socket programs:

1. **Context pointer restrictions**: Cannot pass `ctx` to helper functions after accessing its fields. All context values must be read into local variables first.

2. **Address family**: The `ctx->family` field may not be accessible in all program types. Use the program type to determine the family (e.g., `connect4`/`sendmsg4` = AF_INET, `connect6`/`sendmsg6` = AF_INET6).

3. **Return values**: cgroup/connect and cgroup/sendmsg programs must return 0 (block) or 1 (allow), not negative errno values.

4. **Socket pointer access**: Direct access to `struct sock` via `ctx->sk` is prohibited. Use context fields directly.

### Backward Compatibility

The code patterns used are intentionally conservative to maximize compatibility:

- Extracting context values to local variables works on all kernel versions
- Inferring address family from program type (connect4 = IPv4) is universally correct
- Return values 0/1 are the documented standard for cgroup socket programs

These patterns satisfy both older kernels (which were more lenient) and newer kernels (which are stricter).

### Supported Program Types

- `cgroup/connect4`: TCP connect for IPv4
- `cgroup/connect6`: TCP connect for IPv6
- `cgroup/sendmsg4`: UDP sendmsg for IPv4
- `cgroup/sendmsg6`: UDP sendmsg for IPv6

