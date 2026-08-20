# Make command-jail control masking stable across detached state replacement

## Status

Resolved.

## Problem

Strict detached commands intermittently fail before execution with:

```text
command jail: hide control path .../recovery.json: no such file or directory
```

The supervisor journals command admission, process identity, start, and completion by atomically replacing `recovery.json`. The command jail currently validates and bind-masks that mutable file by pathname. Replacement can race setup, and a successful bind mask is attached to the replaced inode rather than providing a stable boundary for later replacements.

## Desired behavior

- Hide the detached supervisor control topology with a stable directory mount.
- Preserve only explicit command runtime/workspace subtrees beneath the detached state directory.
- Fail closed if the protected tree or any preserved subtree is missing, replaced, or traverses a symlink.
- Keep strict command execution reliable while recovery journaling atomically replaces its files.

## Resolution

Commit `4ca1d6ff` masks the stable detached state directory tree while pinning and restoring only the command runtime/workspace subtrees. It adds regression coverage for atomic recovery manifest replacement, preserved workspace writes, and Landlock composition.
