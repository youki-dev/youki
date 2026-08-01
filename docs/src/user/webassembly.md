# Webassembly

There are 3 things you need to do to run a WebAssembly module with youki.

1. Build youki with one of the wasm feature flags enabled
2. Build a container image with the WebAssembly module
3. Run the container with youki

## Build youki with `wasm-wasmedge`, `wasm-wasmer`, or `wasm-wasmtime` feature flag enabled

- Run `build.sh` with `-f wasm-wasmedge` option.

    ```bash
    ./scripts/build.sh -o . -r -f wasm-wasmedge
    ```

- Run `build.sh` with `-f wasm-wasmer` option.

    ```bash
    ./scripts/build.sh -o . -r -f wasm-wasmer
    ```

- Run `build.sh` with `-f wasm-wasmtime` option.

    ```bash
    ./scripts/build.sh -o . -r -f wasm-wasmtime
    ```

## Build a container image with the WebAssembly module

If you want to run a webassembly module with youki, your config.json has to include either **run.oci.handler** or **module.wasm.image/variant=compat**.

It also needs to specify a valid .wasm (webassembly binary) or .wat (webassembly text format) module as entrypoint for the container. If a wat module is specified it will be compiled to a wasm module by youki before it is executed. The module also needs to be available in the root filesystem of the container obviously.

```json
"ociVersion": "1.0.2-dev",
"annotations": {
    "run.oci.handler": "wasm"
},
"process": {
    "args": [
        "hello.wasm",
        "hello",
        "world"
    ],
...
}
...
```

### Compile a sample wasm module

A simple wasm module can be created by running

```console
rustup target add wasm32-wasip1
cargo new wasm-module --bin
cd ./wasm-module
vi src/main.rs
```

```rust
fn main() {
    println!("Printing args");
    for arg in std::env::args().skip(1) {
        println!("{}", arg);
    }

    println!("Printing envs");
    for envs in std::env::vars() {
        println!("{:?}", envs);
    }  
}
```

Then compile the program to WASI.

```console
cargo build --target wasm32-wasip1
```

### Build a container image with the module

Create a Dockerfile.

```console
vi Dockerfile
```

```Dockerfile
FROM scratch
COPY target/wasm32-wasip1/debug/wasm-module.wasm /
ENTRYPOINT ["/wasm-module.wasm"]
```

Then build a container image with `module.wasm.image/variant=compat` annotation.

```console
buildah build --annotation "module.wasm.image/variant=compat" -t wasm-module .
```

## Run the wasm module with youki and podman

Run podman with youki as runtime.

```bash
podman run --annotation "run.oci.handler=wasm" --runtime /PATH/WHERE/YOU/BUILT/youki localhost/wasm-module 1 2 3
```

The `--annotation "run.oci.handler=wasm"` flag tells youki to use its wasm handler. It is passed explicitly here because the `module.wasm.image/variant=compat` annotation set at build time is not always propagated to the container's `config.json` by podman.

> **Note:** The command above runs rootless, which is podman's default for a non-root user, so `sudo` is not required. If your host is not set up for rootless containers (for example, missing `subuid`/`subgid` configuration) or you need functionality that requires elevated privileges, run the same command with `sudo` (rootful mode).
>
> Make sure `buildah` and `podman` run in the same context (both rootless, or both with `sudo`). They use separate container storage per user (`~/.local/share/containers` for rootless, `/var/lib/containers` for rootful), so building the image with one and running it with the other will fail to find `localhost/wasm-module`.
