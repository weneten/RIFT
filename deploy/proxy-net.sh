# Shared by deploy/setup-server and deploy/publish-panel (after deploy/ask.sh): the Docker
# network a proxy container reaches the web panel from. The container connects to the
# panel's tunnel address from the address its own routing picks, so that is asked in the
# container's network namespace (ip route get), not guessed from the list of its networks.
#
# panel_source_net CONTAINER TARGET_IPV4 -> sets $source_ip and $source_net (the IPv4 network of
# that address, e.g. 172.18.0.0/16), both empty when it cannot be told.
panel_source_net() {
  source_ip=
  source_net=
  _rows=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}/{{.IPPrefixLen}} {{end}}' "$1" 2> /dev/null || true)
  _pid=$(docker inspect -f '{{.State.Pid}}' "$1" 2> /dev/null || true)
  if [ -n "$_pid" ] && [ "$_pid" != 0 ] && command -v nsenter > /dev/null 2>&1; then
    source_ip=$(nsenter -t "$_pid" -n ip -4 route get "$2" 2> /dev/null \
      | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1)
  fi
  _count=0
  for _row in $_rows; do
    is_ip4 "${_row%/*}" && _count=$((_count + 1))
  done
  for _row in $_rows; do
    _ip=${_row%/*}
    _len=${_row#*/}
    is_ip4 "$_ip" || continue
    case $_len in '' | *[!0-9]*) continue ;; esac
    # Without a view into the namespace only a single network is unambiguous.
    if [ -z "$source_ip" ] && [ "$_count" -eq 1 ]; then
      source_ip=$_ip
    fi
    [ "$_ip" = "$source_ip" ] || continue
    source_net=$(int_ip4 $(($(ip4_int "$_ip") & $(mask4 "$_len"))))/$_len
  done
  [ -n "$source_net" ] || source_ip=
}
