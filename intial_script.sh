#!/bin/bash

command_present() {
  type "$1" >/dev/null 2>&1
}

if command_present openssl; then
  openssl_version_output=$(openssl version)
  openssl_version_array=($openssl_version_output)
  echo OPENSSL_VERSION_AKTO=${openssl_version_array[1]} >> ebpf.env
fi

ssl_libraries=("openssl" "bssl")

for library in "${ssl_libraries[@]}"; do

  if ! command_present $library; then
    continue
  fi

  ldd_output=$(ldd $(which $library) | grep ssl)
  ldd_lines=($ldd_output)

  for line in "${ldd_lines[@]}"; do
    ldd_array=($line)

    for word in "${ldd_array[@]}"; do
      if [[ $word == *libssl* ]]; then
        libssl_path=$(whereis $word | cut -d' ' -f2)
        echo ${library^^}_PATH_AKTO=$libssl_path >> ebpf.env
        break
      fi
    done
  done
done
