#!/usr/bin/env bash
# Runs inside the VM. Opens the shell that docs/demo/demo.tape records.
# The shell runs in tmux, and `caption <text>` writes to the bar at the bottom.
set -eu

socket=youki-demo

# A run that stopped halfway leaves these behind.
kubectl delete pod nginx --ignore-not-found >/dev/null
tmux -L "$socket" kill-server 2>/dev/null || true

# The prompt and `caption` go in an rc file: tmux starts the shell through
# another shell, which would drop them from the environment.
rc=$(mktemp)
cat >"$rc" <<'RC'
PS1='\[\e[1;38;2;247;76;0m\]$\[\e[0m\] '
caption() {
	tmux set -g 'status-format[1]' "#[fill=#21262d,bg=#21262d,align=centre]$*"
	clear
}
RC

cd
exec tmux -L "$socket" -f /dev/null new-session "bash --noprofile --rcfile $rc" \; \
	set -as terminal-features ',*:RGB' \; \
	set -g status 2 \; \
	set -g status-style 'bg=default,fg=#9da7b3' \; \
	set -g 'status-format[0]' '' \; \
	set -g 'status-format[1]' ''
