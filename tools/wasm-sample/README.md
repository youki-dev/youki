This is a simple wasm module for testing purposes. It prints out the arguments given to the program and all environment variables. You can compile the module with 

```
cargo build --target wasm32-wasi
```

If you want youki to execute the module you must copy it to the root file system of the container and reference it in the args of the config.json. You must also ensure that the annotations contain `"run.oci.handler": "wasm"` and that youki has been compiled with one of the supported wasm runtimes. For further information please check the [documentation](https://youki-dev.github.io/youki/user/webassembly.html).

```
"ociVersion": "1.0.2-dev",
	"annotations": {
		"run.oci.handler": "wasm"
	},
	"process": {
		"terminal": true,
		"user": {
			"uid": 0,
			"gid": 0
		},
		"args": [
			"/wasm-sample.wasm",
			"hello",
			"wasm"
		],
```
