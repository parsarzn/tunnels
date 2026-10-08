#!/usr/bin/env bash
# curl -fsSL https://raw.githubusercontent.com/parsarzn/tunnels/refs/heads/main/load.sh -o /root/load.sh && bash /root/load.sh
set -Eeuo pipefail

# EDIT ONLY THIS SECTION. IPv4 only. Empty interface = default-route interface.
IN_IF=""
# Local destination IP seen by Linux (use private IP on cloud NAT).
# Empty = all LOCAL addresses on IN_IF.
LISTEN_IP=""
# Optional fixed local egress IPv4; empty = MASQUERADE.
SNAT_IP=""
# Format: "destination_IP|incoming-destination,incoming-destination|weight"
# Same incoming port on multiple destinations = weighted connection balancing.
# The dash is a mapping separator, NOT a port range.
TARGETS=(
  "5.75.198.192|2020-2020,2021-2021,2022-2022,2023-2023,443-443|1"
  "91.107.158.102|3030-3030,3031-3031,3032-3032|1"
)
PROTOCOLS="tcp" # tcp / udp / both
# END CONFIGURATION

die() { echo "ERROR: $*" >&2; exit 1; }
action=${1:-apply}
case "$action" in apply|check|status|remove) ;; *) die "Usage: bash $0 {apply|check|status|remove}";; esac
[[ $EUID == 0 || $action == check ]] || die "Run with sudo/root."
for tool in python3 ip; do command -v "$tool" >/dev/null || die "Install $tool first."; done
if [[ -z $IN_IF ]]; then
  IN_IF=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
fi
[[ $IN_IF =~ ^[a-zA-Z0-9_.:-]+$ ]] || die "Set IN_IF to your incoming network interface."
ip link show dev "$IN_IF" >/dev/null || die "Interface not found: $IN_IF"
if [[ $action != check ]]; then
  for tool in iptables iptables-restore flock systemctl; do command -v "$tool" >/dev/null || die "Install $tool first."; done
  exec 9>/run/port-lb.lock
  flock -n 9 || die "Another port-lb operation is running."
fi
ipt() { iptables -w 10 "$@"; }
hooks() {
  local mode=$1 table parent chain
  while read -r table parent chain; do
    if [[ $mode == add ]]; then
      ipt -t "$table" -C "$parent" -j "$chain" 2>/dev/null || ipt -t "$table" -I "$parent" 1 -j "$chain"
    else
      while ipt -t "$table" -C "$parent" -j "$chain" 2>/dev/null; do ipt -t "$table" -D "$parent" -j "$chain"; done
    fi
  done <<'HOOKS'
nat PREROUTING PLB_PRE
nat POSTROUTING PLB_POST
filter FORWARD PLB_FWD
HOOKS
}
if [[ $action == status ]]; then
  ipt -t nat -nvL PLB_PRE
  ipt -t nat -nvL PLB_POST
  ipt -nvL PLB_FWD
  systemctl --no-pager status port-lb.service || true
  exit 0
fi
if [[ $action == remove ]]; then
  systemctl disable port-lb.service 2>/dev/null || true
  hooks del
  for c in PLB_PRE PLB_POST; do
    if ipt -t nat -S "$c" >/dev/null 2>&1; then ipt -t nat -F "$c"; ipt -t nat -X "$c"; fi
  done
  if ipt -S PLB_FWD >/dev/null 2>&1; then ipt -F PLB_FWD; ipt -X PLB_FWD; fi
  rm -f /etc/systemd/system/port-lb.service
  systemctl daemon-reload
  echo "Removed own rules and boot service. Existing tracked connections expire normally."
  exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 - "$tmp" "$IN_IF" "$LISTEN_IP" "$SNAT_IP" "$PROTOCOLS" "${TARGETS[@]}" <<'PY'
import sys, ipaddress, collections, pathlib
folder, iface, listen, snat, protocols, *rows = sys.argv[1:]
def ipv4(value):
    return str(ipaddress.IPv4Address(value))
try:
    if listen: listen = ipv4(listen)
    if snat: snat = ipv4(snat)
    protos = {'tcp':['tcp'], 'udp':['udp'], 'both':['tcp','udp']}[protocols]
    groups = collections.defaultdict(list)
    seen = set()
    for row in rows:
        address, mappings, weight = row.split('|')
        address = ipv4(address)
        if ipaddress.ip_address(address) in ipaddress.ip_network('203.0.113.0/24'):
            raise ValueError('Replace example destination IPs with real IPs first.')
        weight = int(weight)
        if not 1 <= weight <= 10000: raise ValueError('Weight must be 1..10000')
        for mapping in mappings.split(','):
            source, dest = map(int, mapping.split('-'))
            if not (1 <= source <= 65535 and 1 <= dest <= 65535):
                raise ValueError('Ports must be 1..65535')
            key = (source,address,dest)
            if key in seen: raise ValueError(f'Duplicate mapping: {key}')
            seen.add(key)
            groups[source].append((address,dest,weight))
    if not groups: raise ValueError('TARGETS is empty')
except (ValueError, KeyError) as e:
    sys.exit(f'Invalid configuration: {e}')
pre, post, fwd = [], [], []
local = f'-d {listen}' if listen else '-m addrtype --dst-type LOCAL'
for port, backends in sorted(groups.items()):
    total = sum(b[2] for b in backends)
    for proto in protos:
        remaining = total
        for index, (address, dest, weight) in enumerate(backends):
            random = '' if index == len(backends)-1 else f' -m statistic --mode random --probability {weight/remaining:.11f}'
            pre.append(f'-A PLB_PRE -i {iface} {local} -p {proto} --dport {port}{random} -j DNAT --to-destination {address}:{dest}')
            # Original destination scopes filtering/SNAT to this port forward.
            original = f' --ctorigdst {listen}' if listen else ''
            ct = f'-m conntrack --ctstate DNAT --ctorigdstport {port}{original}'
            nat = f'SNAT --to-source {snat}' if snat else 'MASQUERADE'
            post.append(f'-A PLB_POST -p {proto} -d {address} --dport {dest} {ct} --ctdir ORIGINAL -j {nat}')
            fwd.append(f'-A PLB_FWD -i {iface} -p {proto} -d {address} --dport {dest} {ct} --ctdir ORIGINAL -j ACCEPT')
            fwd.append(f'-A PLB_FWD -o {iface} -p {proto} -s {address} --sport {dest} {ct} --ctdir REPLY -j ACCEPT')
            remaining -= weight
    print(f'{port}: ' + ', '.join(f'{a}:{d} ({w/total:.0%})' for a,d,w in backends))
nat = ['*nat', ':PLB_PRE - [0:0]', ':PLB_POST - [0:0]', '-F PLB_PRE', '-F PLB_POST', *pre, *post, 'COMMIT']
fil = ['*filter', ':PLB_FWD - [0:0]', '-F PLB_FWD', *fwd, 'COMMIT']
pathlib.Path(folder,'rules').write_text('\n'.join(nat+fil)+'\n')
PY
if [[ $action == check ]]; then echo "Configuration valid (no firewall changes)."; exit 0; fi
iptables-restore -w 10 --test --noflush < "$tmp/rules"
install -d -m 700 /etc/port-lb
# Retain a diagnostic snapshot; never flush or restore other applications' rules.
iptables-save > /etc/port-lb/before-last-apply.rules
sysctl -w net.ipv4.ip_forward=1 >/dev/null
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-port-lb.conf
iptables-restore -w 10 --noflush < "$tmp/rules"
hooks add
source_path=$(readlink -f "${BASH_SOURCE[0]}")
if [[ $source_path != /etc/port-lb/port-lb.sh ]]; then
  install -m 700 "$source_path" /etc/port-lb/port-lb.sh
fi
cat > /etc/systemd/system/port-lb.service <<'UNIT'
[Unit]
Description=Kernel IPv4 port forwarding and connection load balancing
Wants=network-online.target
After=network-online.target ufw.service netfilter-persistent.service docker.service

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/port-lb/port-lb.sh apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable port-lb.service >/dev/null
echo "Applied. Persistent script: /etc/port-lb/port-lb.sh"
echo "After editing: sudo bash /etc/port-lb/port-lb.sh apply"
echo "Existing connections retain their previous destination. No health checks."
