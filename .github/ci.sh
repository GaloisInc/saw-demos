#!/usr/bin/env bash
set -Eeuxo pipefail

[[ "$RUNNER_OS" == 'Windows' ]] && IS_WIN=true || IS_WIN=false
BIN=bin
EXT=""
$IS_WIN && EXT=".exe"
mkdir -p "$BIN"

is_exe() { [[ -x "$1/$2$EXT" ]] || command -v "$2" > /dev/null 2>&1; }

install_z3() {
  is_exe "$BIN" "z3" && return

  case "$RUNNER_OS" in
    Linux) file="ubuntu-18.04.zip" ;;
    macOS) file="osx-10.15.7.zip" ;;
    Windows) file="win.zip" ;;
  esac
  curl -o z3.zip -sL "https://github.com/Z3Prover/z3/releases/download/z3-$Z3_VERSION/z3-$Z3_VERSION-x64-$file"

  if $IS_WIN; then 7z x -bd z3.zip; else unzip z3.zip; fi
  cp z3-*/bin/z3$EXT $BIN/z3$EXT
  $IS_WIN || chmod +x $BIN/z3
  rm z3.zip
}

install_cvc4() {
  is_exe "$BIN" "cvc4" && return
  version="${CVC4_VERSION#4.}" # 4.y.z -> y.z

  case "$RUNNER_OS" in
    Linux) file="x86_64-linux-opt" ;;
    Windows) file="win64-opt.exe" ;;
    macOS) file="macos-opt" ;;
  esac
  # Temporary workaround
  if [[ "$RUNNER_OS" == "Linux" ]]; then
    curl -o cvc4$EXT -sL "https://cvc4.cs.stanford.edu/downloads/builds/x86_64-linux-opt/unstable/cvc4-2020-08-18-x86_64-linux-opt"
  else
    curl -o cvc4$EXT -sL "https://github.com/CVC4/CVC4/releases/download/$version/cvc4-$version-$file"
  fi
  $IS_WIN || chmod +x cvc4$EXT
  mv cvc4$EXT "$BIN/cvc4$EXT"
}

install_yices() {
  is_exe "$BIN" "yices" && return
  ext=".tar.gz"
  case "$RUNNER_OS" in
    Linux) file="pc-linux-gnu-static-gmp.tar.gz" ;;
    macOS) file="apple-darwin18.7.0-static-gmp.tar.gz" ;;
    Windows) file="pc-mingw32-static-gmp.zip" && ext=".zip" ;;
  esac
  curl -o "yices$ext" -sL "https://yices.csl.sri.com/releases/$YICES_VERSION/yices-$YICES_VERSION-x86_64-$file"

  if $IS_WIN; then
    7z x -bd "yices$ext"
    mv "yices-$YICES_VERSION"/bin/*.exe "$BIN"
  else
    tar -xzf "yices$ext"
    (cd "yices-$YICES_VERSION" && sudo ./install-yices)
  fi
  rm -rf "yices$ext" "yices-$YICES_VERSION"
}

install_saw() {
  is_exe "$BIN" "saw" && return

  curl -o saw.tar.gz -sL "https://github.com/GaloisInc/saw-script/releases/download/v$SAW_VERSION/saw-$SAW_VERSION-$RUNNER_OS-x86_64.tar.gz"

  tar -xzf saw.tar.gz
  cp "saw-$SAW_VERSION-$RUNNER_OS-x86_64/bin/saw" "$BIN/saw"
  cp "saw-$SAW_VERSION-$RUNNER_OS-x86_64/bin/saw-remote-api" "$BIN/saw-remote-api"
  rm -rf saw.tar.gz "saw-$SAW_VERSION-$RUNNER_OS-x86_64"
}

install_system_deps() {
  install_z3 &
  install_cvc4 &
  install_yices &
  install_saw &
  wait
  export PATH="$BIN:$PATH"
  echo "$BIN" >> "$GITHUB_PATH"
  is_exe "$BIN" z3 && is_exe "$BIN" cvc4 && is_exe "$BIN" yices && is_exe "$BIN" saw && is_exe "$BIN" saw-remote-api
}

output() { echo "::set-output name=$1::$2"; }

COMMAND="$1"
shift

"$COMMAND" "$@"
