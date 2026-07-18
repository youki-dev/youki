This is an experimental project in order to get away from libseccomp.
Ref: https://github.com/youki-dev/youki/issues/2724

```console
# apply sample seccomp filter
$ cargo test --test filter -- --show-output

# output bpf instruction
$ cargo test --test readjson -- --show-output
```
