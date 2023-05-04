#!/bin/bash

# run: "source initial_script.sh" to export the variables to the current shell.

command_present() {
  type "$1" >/dev/null 2>&1
}

if command_present openssl; then
  openssl_version_output=$(openssl version)
  openssl_version_array=($openssl_version_output)
  export OPENSSL_VERSION_AKTO=${openssl_version_array[1]}
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
        export ${library^^}_PATH_AKTO=$libssl_path
        break
      fi
    done
  done
done
