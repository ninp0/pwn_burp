#!/bin/bash
burp_ext_root='/opt/pwn_burp'
gradle_cache_dir="${burp_ext_root}/.gradle"
build_root="$burp_ext_root/build"
build_libs="$build_root/libs"
pwn_burp_backup="${burp_ext_root}.BAK"
swagger_ui_root="${burp_ext_root}/src/main/resources/swagger-ui"
burp_root='/opt/burpsuite'

if [[ -d "${gradle_cache_dir}" ]]; then
  echo "Stopping Gradle Daemon..."
  ./gradlew --stop
fi

if [[ ! -d "${burp_root}" ]]; then
  echo "Creating ${burp_root} directory..."
  sudo mkdir -p "$burp_root"
fi

# Build the project
cd "$burp_ext_root" && \
  ./gradlew clean build shadowJar && \
  tree . > STRUCTURE.txt && \
  sudo cp ${build_libs}/pwn-burp.jar $burp_root/pwn-burp.jar && \
  if [[ -d "${pwn_burp_backup}" ]]; then sudo rm -rf "${pwn_burp_backup}"; fi && \
  sudo cp -a "${burp_ext_root}" "${pwn_burp_backup}"
