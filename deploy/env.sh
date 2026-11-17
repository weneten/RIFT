# Shared by deploy/join and deploy/setup-server: edit one KEY=value line of $env_file.
# Values go through a file, not through sed or the awk command line, so no character in
# them needs escaping. A commented-out `# KEY=` line is replaced in place.
put_env() {
  printf '%s\n' "$2" > "$env_file.tmp.value"
  awk -v key="$1" -v valuefile="$env_file.tmp.value" '
    BEGIN { getline value < valuefile }
    !done && ($0 ~ "^" key "=" || $0 ~ "^# *" key "=") { print key "=" value; done = 1; next }
    { print }
    END { if (!done) print key "=" value }
  ' "$env_file" > "$env_file.tmp"
  mv "$env_file.tmp" "$env_file"
  rm -f "$env_file.tmp.value"
  chmod 600 "$env_file"
}
