# Webassembly

There are 3 things you need to do to run a WebAssembly module with youki.

1. Build youki with wasm-wasmer feature flag enabled
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

If you want to run a webassembly module with youki, your config.json has to include either **runc.oci.handler** or **module.wasm.image/variant=compat"**.

It also needs to specify a valid .wasm (webassembly binary) or .wat (webassembly test) module as entrypoint for the container. If a wat module is specified it will be compiled to a wasm module by youki before it is executed. The module also needs to be available in the root filesystem of the container obviously.

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
rustup target add wasm32-wasi
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
cargo build --target wasm32-wasi
```

### Build a container image with the module

Create a Dockerfile.

```console
vi Dockerfile
```

```Dockerfile
FROM scratch
COPY target/wasm32-wasi/debug/wasm-module.wasm /
ENTRYPOINT ["wasm-module.wasm"]
```

Then build a container image with `module.wasm.image/variant=compat` annotation. [^1]

```console
sudo buildah build --annotation "module.wasm.image/variant=compat" -t wasm-module .
```

## Run the wasm module with youki and podman

Run podman with youki as runtime. [^1]

```bash
sudo podman --runtime /PATH/WHARE/YOU/BUILT/WITH/WASM-WASMER/youki run localhost/wasm-module 1 2 3
```

[^1]: You might need `sudo` because of [#719](https://github.com/youki-dev/youki/issues/719).
