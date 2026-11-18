# Shared by the deploy scripts: read and edit KEY=value lines of $env_file.
# Values go through a file, not through sed or the awk command line, so no character in
# them needs escaping.

# put_env KEY VALUE: sets KEY. A commented-out `# KEY=` line is replaced in place; a later
# second KEY= line, which would win over the first, is dropped.
put_env() {
  printf '%s\n' "$2" > "$env_file.tmp.value"
  awk -v key="$1" -v valuefile="$env_file.tmp.value" '
    BEGIN { getline value < valuefile }
    !done && ($0 ~ "^" key "=" || $0 ~ "^# *" key "=") { print key "=" value; done = 1; next }
    done && $0 ~ "^" key "=" { next }
    { print }
    END { if (!done) print key "=" value }
  ' "$env_file" > "$env_file.tmp"
  mv "$env_file.tmp" "$env_file"
  rm -f "$env_file.tmp.value"
  chmod 600 "$env_file"
}

# default_env KEY DEFAULT: returns KEY to RIFT's default by commenting it out. The active
# line becomes `# KEY=DEFAULT`, or is dropped when a commented line for KEY already exists.
default_env() {
  printf '# %s=%s\n' "$1" "$2" > "$env_file.tmp.value"
  awk -v key="$1" -v valuefile="$env_file.tmp.value" '
    BEGIN { getline line < valuefile }
    NR == FNR { if ($0 ~ "^# *" key "=") commented = 1; next }
    $0 ~ "^" key "=" { if (!commented) { print line; commented = 1 }; next }
    { print }
  ' "$env_file" "$env_file" > "$env_file.tmp"
  mv "$env_file.tmp" "$env_file"
  rm -f "$env_file.tmp.value"
  chmod 600 "$env_file"
}

# get_env KEY: the value of the last active KEY= line, without surrounding quotes.
get_env() {
  [ -f "$env_file" ] || return 0
  sed -n "s/^$1=//p" "$env_file" | tail -n 1 | sed "s/^\"\(.*\)\"\$/\1/; s/^'\(.*\)'\$/\1/"
}
