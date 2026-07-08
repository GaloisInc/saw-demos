#!/usr/bin/env bash
set -Eeuxo pipefail

[[ "$RUNNER_OS" == 'Windows' ]] && IS_WIN=true || IS_WIN=false
BIN=bin
EXT=""
$IS_WIN && EXT=".exe"
mkdir -p "$BIN"

is_exe() { [[ -x "$1/$2$EXT" ]] || command -v "$2" > /dev/null 2>&1; }

install_saw() {
  is_exe "$BIN" "saw" && return

  local SAW_OS
  case "$RUNNER_OS" in
      # FUTURE: ideally we could autodetect the OS version here
      Linux) SAW_OS=ubuntu-24.04;;
      macOS) SAW_OS=macos-15;;
      Windows) SAW_OS=windows-2022;;
      *)
          echo "Unexpected RUNNER_OS $RUNNER_OS" 1>&2
          echo "Help?"
          exit 1
          ;;
  esac
  local NAME=saw-$SAW_VERSION-$SAW_OS-$RUNNER_ARCH

  curl -o saw.tar.gz -sL "https://github.com/GaloisInc/saw-script/releases/download/v$SAW_VERSION/$NAME.tar.gz"

  tar -xzf saw.tar.gz
  cp "$NAME/bin/saw" "$BIN/saw"
  cp "$NAME/bin/saw-remote-api" "$BIN/saw-remote-api"
  rm -rf saw.tar.gz "$NAME"
}

install_system_deps() {
  install_saw
  export PATH="$BIN:$PATH"
  echo "$BIN" >> "$GITHUB_PATH"
  is_exe "$BIN" z3 && is_exe "$BIN" cvc5 && is_exe "$BIN" yices && is_exe "$BIN" abc
  is_exe "$BIN" saw && is_exe "$BIN" saw-remote-api
}

output() { echo "::set-output name=$1::$2"; }

COMMAND="$1"
shift

"$COMMAND" "$@"
