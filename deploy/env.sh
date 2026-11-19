# Shared by the deploy scripts: read and edit KEY=value lines of $env_file.
# Values go through a file, not through sed or the awk command line, so no character in
# them needs escaping.

# put_env KEY VALUE: sets KEY. A commented-out `# KEY=` line is replaced in place; a later
# second KEY= line, which would win over the first, is dropped.
put_env() {
  _umask=$(umask)
  umask 077
  printf '%s\n' "$2" > "$env_file.tmp.value"
  awk -v key="$1" -v valuefile="$env_file.tmp.value" '
    BEGIN { getline value < valuefile }
    !done && ($0 ~ "^" key "=" || $0 ~ "^# *" key "=") { print key "=" value; done = 1; next }
    done && $0 ~ "^" key "=" { next }
    { print }
    END { if (!done) print key "=" value }
  ' "$env_file" > "$env_file.tmp"
  replace_env
}

# default_env KEY DEFAULT: returns KEY to RIFT's default by commenting it out. The active
# line becomes `# KEY=DEFAULT`, or is dropped when a commented line for KEY already exists.
default_env() {
  _umask=$(umask)
  umask 077
  printf '# %s=%s\n' "$1" "$2" > "$env_file.tmp.value"
  awk -v key="$1" -v valuefile="$env_file.tmp.value" '
    BEGIN { getline line < valuefile }
    NR == FNR { if ($0 ~ "^# *" key "=") commented = 1; next }
    $0 ~ "^" key "=" { if (!commented) { print line; commented = 1 }; next }
    { print }
  ' "$env_file" "$env_file" > "$env_file.tmp"
  replace_env
}

# env_owner: who the .env belongs to, as UID:GID. The user who ran the script with sudo, so
# that user's `docker compose` reads it without sudo; run as root without sudo, it keeps its
# owner. Mode 0600 keeps the secrets in it (panel password, invitation token) from others.
env_owner() {
  if [ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" != 0 ]; then
    printf '%s:%s' "$SUDO_UID" "${SUDO_GID:-$SUDO_UID}"
  elif [ -e "$env_file" ]; then
    stat -c '%u:%g' "$env_file"
  fi
}

# replace_env: puts $env_file.tmp in place of $env_file, mode 0600, with its owner.
replace_env() {
  _owner=$(env_owner)
  chmod 600 "$env_file.tmp"
  [ -z "$_owner" ] || chown "$_owner" "$env_file.tmp"
  mv "$env_file.tmp" "$env_file"
  rm -f "$env_file.tmp.value"
  umask "$_umask"
}

# get_env KEY: the value of the last active KEY= line, without surrounding quotes.
get_env() {
  [ -f "$env_file" ] || return 0
  sed -n "s/^$1=//p" "$env_file" | tail -n 1 | sed "s/^\"\(.*\)\"\$/\1/; s/^'\(.*\)'\$/\1/"
}

# The closing list of next steps, the same in every deploy script: a heading, then each step
# as what it does and, indented below it, the command. RIFT_NO_NEXT_STEPS=1 leaves it out
# (deploy/setup-server sets it for the scripts it runs and prints one list itself).
next_steps() {
  [ -z "${RIFT_NO_NEXT_STEPS:-}" ] || return 0
  printf '\n%s\n' "${1:-Next steps:}"
}
next_step() {
  [ -z "${RIFT_NO_NEXT_STEPS:-}" ] || return 0
  printf '\n  %s:\n    %s\n' "$1" "$2"
}
