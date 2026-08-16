#!/usr/bin/env bash
# Add swap and tune swappiness for a development machine.
#
# Run with:   sudo ./scripts/setup-swap.sh
#
# Why this is needed here: the machine has 23 GiB of RAM but only 2 GiB of
# swap, and after days of uptime that swap sits full. When a large build
# allocates quickly the kernel has nowhere to page out idle memory, so it
# starts killing processes instead. An editor is a large, easy target.
#
# The script is idempotent: running it twice does not create a second file or
# duplicate the fstab entry.

set -euo pipefail

SWAPFILE="${SWAPFILE:-/swapfile2}"
SIZE_GB="${SIZE_GB:-16}"
SWAPPINESS="${SWAPPINESS:-10}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run this with sudo" >&2
  exit 1
fi

echo "Before:"
free -h | sed 's/^/  /'
echo

# --- create the file ---------------------------------------------------------

if swapon --show=NAME --noheadings | grep -qx "$SWAPFILE"; then
  echo "$SWAPFILE is already active, leaving it alone"
else
  if [ ! -f "$SWAPFILE" ]; then
    avail_gb=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')
    if [ "$avail_gb" -lt $((SIZE_GB + 10)) ]; then
      echo "not enough free space: ${avail_gb}G available, need ${SIZE_GB}G plus headroom" >&2
      exit 1
    fi

    echo "creating ${SIZE_GB}G at $SWAPFILE"
    # fallocate is instant but leaves holes on some filesystems, which swapon
    # refuses. dd is slower and always produces a file swapon accepts.
    if ! fallocate -l "${SIZE_GB}G" "$SWAPFILE" 2>/dev/null; then
      dd if=/dev/zero of="$SWAPFILE" bs=1M count=$((SIZE_GB * 1024)) status=progress
    fi
  fi

  # A swap file readable by anyone leaks whatever was paged out of any process.
  chmod 600 "$SWAPFILE"
  mkswap "$SWAPFILE" >/dev/null
  swapon "$SWAPFILE"
  echo "activated $SWAPFILE"
fi

# --- make it survive a reboot ------------------------------------------------

if grep -qs "^$SWAPFILE " /etc/fstab; then
  echo "fstab entry already present"
else
  cp /etc/fstab "/etc/fstab.backup-$(date +%Y%m%d%H%M%S)"
  printf '%s none swap sw 0 0\n' "$SWAPFILE" >> /etc/fstab
  echo "added to /etc/fstab, a backup of the old file is beside it"
fi

# --- swappiness --------------------------------------------------------------

# The default of 60 suits a machine that is short on RAM. With 23 GiB, paging
# out things that are still wanted costs more than it saves. 10 keeps swap as
# an overflow reserve rather than a routine destination.
sysctl -w vm.swappiness="$SWAPPINESS" >/dev/null
CONF=/etc/sysctl.d/99-rotelyx-swappiness.conf
printf 'vm.swappiness=%s\n' "$SWAPPINESS" > "$CONF"
echo "swappiness set to $SWAPPINESS, persisted in $CONF"

echo
echo "After:"
free -h | sed 's/^/  /'
swapon --show | sed 's/^/  /'

cat <<'NOTE'

Note on the old swap: the existing /swapfile stays full until the pages in it
are touched again or something is restarted. That is normal and it is not a
problem now that there is somewhere else to page to. If you want it drained
immediately, and you have the free RAM to hold it:

    sudo swapoff /swapfile && sudo swapon /swapfile
NOTE
