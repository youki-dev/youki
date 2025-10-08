# Runtime Test

**Note** that these tests resides in /tests/runtimetest at the time of writing.

This crate provides a binary which is used by integration tests to verify that the restrictions and constraints applied to the container are upheld by the container process, from inside the container process. This runs the tests one-by-one, and the failing test prints the error to the stderr.

## Notes

This binary must be compiled with the option of static linking to crt0 given to the rustc. If compiled without it, it will add a linking to /lib64/ld-linux-x86-64.so . The binary compiled this way cannot be run inside the container process, as they do not have access to /lib64/... Thus the runtime test must be statically linked to crt0.

While developing, originally this was added to the common workspace of all crates in youki. But then it was realized that this was quite inefficient because :

- All packages except runtimetest will be compiled with dynamic linking
- Runtimetest will be compiled with static linking

Now runtimetest needs at least `oci-spec` and `nix` package for its operations, which are also dependencies of other packages in the workspace. Thus both of these, and recursively their dependencies must be compiled twice, each time, once for dynamic linking and once for static. The took a long time in the compilation stage, especially when developing / adding new tests. Separating runtimetest from the workspace allows it to have a separate target/ directory, where it can store the statically compiled dependencies, and the workspace can have its target/ directory, where it can store its dynamically compiled dependencies. That way only the crates which have changes need to be compiled (runtimetest or integration test), and not their dependencies.

In case in future this separation is not required, or some other configuration is chosen, make sure the multiple compilation issue does not arise, or the advantages of new method outweigh the time spent in double compilation.

To see if a binary can be run inside the container process, run

```console
readelf -l path/to/binary |grep "program interpreter"
```

`[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]` means that the binary is not statically linked, and cannot be run inside the container process. If the above command gives no output, that means it does not require any program interpreter and can be run inside the container.

Another way is to run

```console
file path/to/binary
```

```console
./youki: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=...., for GNU/Linux 3.2.0, with debug_info, not stripped`
```

This output indicates that the binary is dynamically linked, thus cannot be run inside the container process

```console
./runtimetest: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=...., for GNU/Linux 3.2.0, with debug_info, not stripped
```

This output indicates that the binary is statically linked, and can be run inside the container process

Some links to help :

- [how to generate static executable](https://stackoverflow.com/questions/31770604/how-to-generate-statically-linked-executables)
- [understanding the error which dynamically linked library gives](https://superuser.com/questions/248512/why-do-i-get-command-not-found-when-the-binary-file-exists)
- [Rust cargo config for rustflags](https://doc.rust-lang.org/cargo/reference/config.html)
