# Shared by deploy/setup-server and deploy/join: questions with defaults, values from
# options, and checks of the values before anything is written.
#
# The caller defines fail(), sources env.sh, sets $env_file, $env_existed (1 when the .env
# was there before this run), $interactive (1 when a terminal answers) and builtin KEY
# (RIFT's default of a setting). Values live in val_KEY, values from options in preset_KEY.
# KEY is always a literal of the calling script or was checked against known_key, so the
# evals below never see other text.

asking=1

get() { eval "printf '%s' \"\${val_$1-}\""; }
put() { eval "val_$1=\$2"; }
preset() { eval "preset_$1=\$2; has_preset_$1=1"; }
has_preset() { eval "[ -n \"\${has_preset_$1-}\" ]"; }

# The value of KEY in the .env that existed before this run, else RIFT's default.
current() {
  if [ -n "$env_existed" ]; then
    _v=$(get_env "$1")
    if [ -n "$_v" ]; then
      printf '%s' "$_v"
      return
    fi
  fi
  builtin "$1"
}
# Whether the existing .env sets one of the KEYs to something else than RIFT's default.
changed() {
  for _k in "$@"; do
    [ "$(current "$_k")" = "$(builtin "$_k")" ] || return 0
  done
  return 1
}

heading() {
  [ -n "$interactive" ] || return 0
  printf '\n== %s ==\n' "$1" > /dev/tty
}
note() {
  [ -n "$interactive" ] && [ -n "$asking" ] || return 0
  printf '  %s\n' "$*" > /dev/tty
}

# ask "Question" DEFAULT [CHECK]: sets $answer. Enter takes the default, - clears it, and an
# answer CHECK refuses is asked again. Without a terminal (or in a declined group) the
# default is the answer.
ask() {
  _q=$1 _d=$2 _c=${3-}
  if [ -z "$interactive" ] || [ -z "$asking" ]; then
    answer=$_d
    if [ -n "$_c" ] && ! "$_c" "$answer"; then
      fail "${_key:+$_key: }$why"
    fi
    return 0
  fi
  while :; do
    if [ -n "$_d" ]; then
      printf '  %s [%s]: ' "$_q" "$_d" > /dev/tty
    else
      printf '  %s: ' "$_q" > /dev/tty
    fi
    read -r answer < /dev/tty || answer=
    case $answer in
      '') answer=$_d ;;
      -) answer= ;;
    esac
    if [ -z "$_c" ] || "$_c" "$answer"; then
      return 0
    fi
    printf '    %s\n' "$why" > /dev/tty
  done
}

# setting KEY "Question" [CHECK [DEFAULT]]: the value an option gave for KEY (checked), else
# the answer to the question. DEFAULT defaults to current KEY. Stores val_KEY and $answer.
setting() {
  _key=$1
  if has_preset "$_key"; then
    eval "answer=\$preset_$_key"
    [ -n "$answer" ] || answer=$(builtin "$_key")
    if [ -n "${3-}" ] && ! "$3" "$answer"; then
      fail "$_key=$answer: $why"
    fi
  elif [ "$#" -ge 4 ]; then
    ask "$2" "$4" "${3-}"
  else
    ask "$2" "$(current "$_key")" "${3-}"
  fi
  put "$_key" "$answer"
  _key=
}

# yes_no "Question" y|n -> 0 for yes.
yes_no() {
  _r=$2
  if [ -n "$interactive" ] && [ -n "$asking" ]; then
    _h="y/N"
    [ "$2" = y ] && _h="Y/n"
    printf '  %s [%s]: ' "$1" "$_h" > /dev/tty
    read -r _r < /dev/tty || _r=
    _r=${_r:-$2}
  fi
  case $_r in [yY]*) return 0 ;; *) return 1 ;; esac
}
# flag KEY "Question": a true/false setting asked as yes/no.
flag() {
  _key=$1
  if has_preset "$_key"; then
    eval "answer=\$preset_$_key"
    [ -n "$answer" ] || answer=$(builtin "$_key")
    is_bool "$answer" || fail "$_key=$answer: $why"
  else
    _d=n
    [ "$(current "$_key")" = true ] && _d=y
    if yes_no "$2" "$_d"; then answer=true; else answer=false; fi
  fi
  put "$_key" "$answer"
  _key=
}

# group "Question" [y]: asks a group of rarely changed settings only after a yes; otherwise
# they keep their value. y makes yes the default (the .env already changed one of them).
group() {
  asking=1
  if yes_no "$1" "${2:-n}"; then
    return 0
  fi
  asking=
  return 0
}
end_group() { asking=1; }

# secret "Question": hidden input, typed twice; sets $answer (empty on Enter).
secret() {
  while :; do
    printf '  %s: ' "$1" > /dev/tty
    stty -echo < /dev/tty 2> /dev/null || true
    read -r answer < /dev/tty || answer=
    stty echo < /dev/tty 2> /dev/null || true
    printf '\n' > /dev/tty
    [ -n "$answer" ] || return 0
    if [ -n "${2-}" ] && ! "$2" "$answer"; then
      printf '    %s\n' "$why" > /dev/tty
      continue
    fi
    printf '  Again: ' > /dev/tty
    stty -echo < /dev/tty 2> /dev/null || true
    read -r _again < /dev/tty || _again=
    stty echo < /dev/tty 2> /dev/null || true
    printf '\n' > /dev/tty
    [ "$_again" = "$answer" ] && return 0
    printf '    the two entries differ; once more\n' > /dev/tty
  done
}

# ---------- checks: 0 when valid, else 1 with the reason in $why ----------

is_bool() {
  why="true or false"
  case $1 in true | false) return 0 ;; esac
  return 1
}
one_of() {
  _x=$1
  shift
  why="one of: $*"
  for _o in "$@"; do
    [ "$_x" = "$_o" ] && return 0
  done
  return 1
}
is_port() {
  why="a port is a number from 1 to 65535"
  case $1 in '' | *[!0-9]*) return 1 ;; esac
  [ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
is_ip4() {
  why="not an IPv4 address: $1"
  printf '%s\n' "$1" | grep -Eq '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
}
# A loose IPv6 check: hex groups and colons, at most one ::. The server checks the rest.
is_ip6() {
  why="not an IPv6 address: $1"
  case $1 in *:*) ;; *) return 1 ;; esac
  case $1 in *:::* | *::*::*) return 1 ;; esac
  printf '%s\n' "$1" | grep -Eq '^[0-9A-Fa-f:.]+$'
}
is_ip() { is_ip4 "$1" || is_ip6 "$1" || { why="not an IP address: $1"; return 1; }; }
ip4_int() {
  _o=$IFS
  IFS=.
  # shellcheck disable=SC2086
  set -- $1
  IFS=$_o
  echo $((($1 << 24) + ($2 << 16) + ($3 << 8) + $4))
}
int_ip4() { echo "$(($1 >> 24 & 255)).$(($1 >> 16 & 255)).$(($1 >> 8 & 255)).$(($1 & 255))"; }
mask4() {
  if [ "$1" -eq 0 ]; then echo 0; else echo $(((4294967295 << (32 - $1)) & 4294967295)); fi
}
is_net4() {
  case $1 in */*) ;; *) why="not an IPv4 network like 10.13.0.0/24: $1"; return 1 ;; esac
  _len=${1#*/}
  case $_len in '' | *[!0-9]*) why="not an IPv4 network like 10.13.0.0/24: $1"; return 1 ;; esac
  is_ip4 "${1%/*}" && [ "$_len" -le 32 ] || { why="not an IPv4 network like 10.13.0.0/24: $1"; return 1; }
}
is_net6() {
  case $1 in */*) ;; *) why="not an IPv6 network like fd88:5249:4654::/64: $1"; return 1 ;; esac
  _len=${1#*/}
  case $_len in '' | *[!0-9]*) why="not an IPv6 network: $1"; return 1 ;; esac
  is_ip6 "${1%/*}" && [ "$_len" -le 128 ] || { why="not an IPv6 network like fd88:5249:4654::/64: $1"; return 1; }
}
is_private4() {
  _n=$(ip4_int "$1")
  [ $((_n >> 24)) -eq 10 ] || [ $((_n >> 20)) -eq 2753 ] || [ $((_n >> 16)) -eq 49320 ]
}
# Whether the IPv4 networks (or single addresses) $1 and $2 overlap.
overlap4() {
  case $1 in */*) _a=$1 ;; *) _a=$1/32 ;; esac
  case $2 in */*) _b=$2 ;; *) _b=$2/32 ;; esac
  _l=${_a#*/}
  [ "${_b#*/}" -lt "$_l" ] && _l=${_b#*/}
  _m=$(mask4 "$_l")
  [ $(($(ip4_int "${_a%/*}") & _m)) -eq $(($(ip4_int "${_b%/*}") & _m)) ]
}
# The first host address of an IPv4 network.
first_host4() {
  _m=$(mask4 "${1#*/}")
  int_ip4 $((($(ip4_int "${1%/*}") & _m) + 1))
}
# Routes of the host (main table, not RIFT's own) that overlap the IPv4 network $1.
route_overlaps() {
  ip -4 route show 2> /dev/null | awk '$1 != "default" && $0 !~ / dev rift/ {print $1}' | sort -u \
    | while read -r _r; do
      is_ip4 "${_r%/*}" || continue
      if overlap4 "$_r" "$1"; then printf '%s ' "$_r"; fi
    done
}
# Comma-separated list: every item passes CHECK. is_list CHECK VALUE [empty-ok]
is_list() {
  _check=$1
  [ -n "$2" ] || { [ -n "${3-}" ] && return 0; why="give at least one entry"; return 1; }
  _o=$IFS
  IFS=,
  for _i in $2; do
    IFS=$_o
    "$_check" "$_i" || return 1
    IFS=,
  done
  IFS=$_o
  return 0
}
is_net_or_ip() {
  is_ip "$1" || is_net4 "$1" || is_net6 "$1" || { why="not an address or network: $1"; return 1; }
}
is_email() {
  why="an e-mail address is needed"
  [ -n "$1" ] || return 1
  why="not an e-mail address: $1"
  printf '%s\n' "$1" | grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
}
maybe_email() { [ -z "$1" ] || is_email "$1"; }
is_domain() {
  why="not a domain name: $1"
  printf '%s\n' "$1" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
}
maybe_domain() { [ -z "$1" ] || is_domain "$1"; }
# A DNS name or an IP address, without scheme, port or path (the server's own rule).
is_host() {
  why="a DNS name or IP address without scheme, port or path: $1"
  [ -n "$1" ] || return 1
  is_ip4 "$1" && return 0
  case $1 in *:*) is_ip6 "$1" && return 0; why="a DNS name or IP address without scheme, port or path: $1"; return 1 ;; esac
  [ "${#1}" -le 253 ] || return 1
  printf '%s\n' "$1" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
}
is_version() {
  why="latest or a release such as 1.0.0"
  printf '%s\n' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
}
