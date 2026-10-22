#!/usr/bin/env bash
# Read-only inventory of PHP binaries, package versions, and PHP-FPM units.
set -u

printf '%s\n' 'PHP host inventory (read-only)'
printf 'timestamp_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf unknown)"
printf 'platform=%s\n' "$(uname -srm 2>/dev/null || printf unknown)"

declare -A seen=()
printf '\n%s\n' '== PHP runtimes found in common executable paths =='
for path in /usr/bin/php* /usr/sbin/php* /usr/local/bin/php* /usr/local/sbin/php*; do
  [[ -x "$path" && ! -d "$path" ]] || continue
  base=${path##*/}
  [[ "$base" =~ ^php([0-9]+(\.[0-9]+)?(-fpm|-cgi)?|(-fpm|-cgi)([0-9]+(\.[0-9]+)?)?)?$ ]] || continue
  [[ -z "${seen[$path]+present}" ]] || continue
  seen[$path]=1
  printf '\n-- %s --\n' "$path"
  "$path" -v 2>&1 | sed -n '1,4p'
  if [[ "$base" == php ]]; then
    printf '%s\n' 'Configuration file paths (values are not printed):'
    "$path" --ini 2>&1 | sed -n '1,8p'
  fi
done

printf '\n%s\n' '== PHP packages reported by the system package manager =='
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${binary:Package}\t${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null \
    | awk '$1 ~ /^(php|libapache2-mod-php)/ {print}'
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 'php*' 2>/dev/null | sort
elif command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | awk '$1 ~ /^php/ {print}' | sort
else
  printf '%s\n' 'No supported package query command found (dpkg-query, rpm, apk).'
fi

printf '\n%s\n' '== PHP-FPM systemd units =='
if command -v systemctl >/dev/null 2>&1; then
  units=$(systemctl list-units --all --type=service --no-legend --no-pager 'php*-fpm.service' 2>/dev/null || true)
  if [[ -n "$units" ]]; then
    printf '%s\n' "$units" | awk '{print $1 "\t" $3 "\t" $4}'
  else
    printf '%s\n' 'No matching PHP-FPM units found or systemd is unavailable.'
  fi
else
  printf '%s\n' 'systemctl not available; inspect the active web runtime through its supervisor/container/provider.'
fi

printf '\n%s\n' 'Note: CLI, package, and unit inventory do not prove which runtime serves web traffic.'
