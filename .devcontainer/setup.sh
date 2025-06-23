#!/bin/bash
set -e

echo "Setting up permissions..."
sudo chown -R vscode:vscode /usr/local/cargo/registry
sudo chown -R vscode:vscode /home/vscode/command-history

echo "Creating directories..."
mkdir -p /home/vscode/.local/share/fish

echo "Creating history files..."
touch /home/vscode/command-history/.bash_history
touch /home/vscode/command-history/.zsh_history
touch /home/vscode/command-history/fish_history

echo "Creating symlinks..."
create_history_symlink() {
  local source="$1"
  local target="$2"
  mkdir -p "$(dirname "$target")"
  if [ -L "$target" ] && [ "$(readlink "$target")" = "$source" ]; then
    echo "Symlink already exists: $target -> $source"
    return 0
  fi
  if [ -e "$target" ] || [ -L "$target" ]; then
    echo "Removing existing: $target"
    rm -f "$target"
  fi
  ln -sf "$source" "$target"
  echo "Created symlink: $target -> $source"
}
create_history_symlink "/home/vscode/command-history/.bash_history" "/home/vscode/.bash_history"
create_history_symlink "/home/vscode/command-history/.zsh_history" "/home/vscode/.zsh_history"
create_history_symlink "/home/vscode/command-history/fish_history" "/home/vscode/.local/share/fish/fish_history"

echo "Configuring shell history persistence..."
setup_bash_history() {
  local bashrc="$HOME/.bashrc"
  echo "Configuring bash history..."
  if ! grep -q "export HISTCONTROL.*ignoredups" "$bashrc"; then
    echo 'export HISTCONTROL=ignoredups:erasedups' >> "$bashrc"
    echo "Added HISTCONTROL setting"
  fi
  if ! grep -q "shopt -s histappend" "$bashrc"; then
    echo 'shopt -s histappend' >> "$bashrc"
    echo "Added histappend setting"
  fi
  if ! grep -q "history -a" "$bashrc"; then
    echo 'PROMPT_COMMAND="history -a; $PROMPT_COMMAND"' >> "$bashrc"
    echo "Added PROMPT_COMMAND setting"
  fi
  echo "Bash history configuration completed"
}
setup_bash_history

echo "Setup completed!"
