m2n() { ip -br link 2>/dev/null | awk -v m="$1" 'tolower($3)==tolower(m){print $1; exit}'; }
slaves=""
for mac in __MACS__; do
  n=$(m2n "$mac")
  if [ -n "$n" ]; then slaves="$slaves $n"; fi
done
if [ -z "$slaves" ]; then
  echo "# bond __BOND__ : aucune NIC membre trouvee, config d-i conservee" > /etc/network/interfaces.d/pxe-bond-__BOND__
  exit 0
fi
for n in $slaves; do
  awk -v n="$n" '
    /^(auto|allow-[a-z-]+|iface)[[:space:]]/ { if ($2 == n) { drop = ($1 == "iface"); next }; drop = 0 }
    /^(source|source-directory|mapping|no-[a-z-]+)[[:space:]]/ { drop = 0 }
    drop && /^[[:space:]]/ { next }
    { print }
  ' /etc/network/interfaces > /etc/network/interfaces.pxe && mv /etc/network/interfaces.pxe /etc/network/interfaces
done
{
  for n in $slaves; do printf 'iface %s inet manual\n\n' "$n"; done
  cat <<'PXEBOND'
__STANZA__
PXEBOND
  if [ "__ACTIVE_BACKUP__" = 1 ]; then
    set -- $slaves
    printf '    bond-primary %s\n' "$1"
  fi
  echo "    bond-slaves$slaves"
} > /etc/network/interfaces.d/pxe-bond-__BOND__
