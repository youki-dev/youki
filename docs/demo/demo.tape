# Records docs/demo.gif. The demo runs in a Lima VM, so the host stays as it is.
# Run from the repository root:
#   limactl start --name=youki-demo docs/demo/lima.yaml
#   limactl shell youki-demo "$PWD/docs/demo/prepare.sh"
#   vhs docs/demo/demo.tape
# Needs vhs and Lima on the host.

Output docs/demo.gif

Require limactl

Set Shell bash
Set FontSize 20
Set Width 1340
Set Height 600
Set WindowBar Colorful
Set Padding 40
Set TypingSpeed 50ms
Set Theme { "name": "youki", "background": "#161b22", "foreground": "#e6edf3", "cursor": "#f74c00", "selection": "#3b4452", "black": "#484f58", "red": "#ff7b72", "green": "#3fb950", "yellow": "#d29922", "blue": "#58a6ff", "magenta": "#bc8cff", "cyan": "#39c5cf", "white": "#b1bac4", "brightBlack": "#6e7681", "brightRed": "#ffa198", "brightGreen": "#56d364", "brightYellow": "#e3b341", "brightBlue": "#79c0ff", "brightMagenta": "#d2a8ff", "brightCyan": "#56d4dd", "brightWhite": "#ffffff" }

Hide
Type@1ms `limactl shell youki-demo "$PWD/docs/demo/session.sh"` Enter
Wait+Screen@120s /(?m)^\$\s*$/
Type@1ms "caption 'youki is a container runtime written in Rust'" Enter
Sleep 500ms
Show

Sleep 1s
Type "youki --version" Enter
Sleep 3s

Hide
Type@1ms "caption 'Docker: pass --runtime youki'" Enter
Sleep 500ms
Show

Sleep 1s
Type "docker run --rm -it --runtime youki busybox" Enter
Wait+Screen / #/
Sleep 1s
Type 'echo "Hello from youki!"' Enter
Sleep 1.5s
Type "ps" Enter
Sleep 2.5s
Type "exit" Enter
Wait+Screen@30s /exit\s+\$/
Sleep 1.5s

Hide
Type@1ms "caption 'Kubernetes: set runtimeClassName to youki'" Enter
Sleep 500ms
Show

Sleep 1s
Type `kubectl run nginx --image=nginx:alpine --overrides='{"spec":{"runtimeClassName":"youki"}}'` Enter
Wait+Screen@30s /created/
Sleep 1s
Type "kubectl wait --for=condition=Ready pod/nginx" Enter
Wait+Screen@120s /condition met/
Sleep 1s
Type "kubectl get pod nginx" Enter
Wait+Screen@30s /Running/
Sleep 3s

Hide
Type@1ms "caption 'WebAssembly: run a wasm module as a container'" Enter
Sleep 500ms
Show

Sleep 1s
Type "docker run --rm --runtime youki --annotation run.oci.handler=wasm hello-wasm" Enter
Wait+Screen@30s /Hello from WebAssembly/
Sleep 4s

Hide
Type@1ms "kubectl delete pod nginx --wait=false; exit" Enter
Sleep 3s
