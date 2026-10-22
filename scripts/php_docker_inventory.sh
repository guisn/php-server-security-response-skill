#!/usr/bin/env bash
# Read-only inventory of explicitly selected Docker containers.
set -u

if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'ERROR: docker CLI not found.' >&2
  exit 127
fi

if (( $# == 0 )); then
  printf '%s\n' 'Running containers (name, image, status):'
  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
  docker_status=$?
  printf '\n%s\n' 'Pass one or more exact container names/IDs to inspect PHP runtime versions.'
  exit "$docker_status"
fi

status=0
for target in "$@"; do
  if [[ ! "$target" =~ ^[[:alnum:]][[:alnum:]_.-]{0,127}$ ]]; then
    printf 'ERROR: invalid container name or ID: %q\n' "$target" >&2
    status=2
    continue
  fi

  printf '\n== Container: %s ==\n' "$target"
  if ! docker inspect --format 'name={{.Name}} image={{.Config.Image}} state={{.State.Status}}' "$target"; then
    status=1
    continue
  fi

  state=$(docker inspect --format '{{.State.Status}}' "$target" 2>/dev/null || true)
  if [[ "$state" != running ]]; then
    printf 'SKIP: container state is %s; no command was run inside it.\n' "${state:-unknown}"
    continue
  fi

  printf '%s\n' 'Active process names (PID and command name only):'
  if processes=$(docker top "$target" -eo pid,comm 2>/dev/null); then
    printf '%s\n' "$processes" | awk 'NR <= 81 {print} NR == 82 {print "... process list truncated at 80 entries"; exit}'
  else
    printf '%s\n' 'Process listing unavailable with this Docker host; continue with runtime and service configuration evidence.'
  fi

  if ! docker exec "$target" sh -c '
    found=0
    seen="|"
    check_binary() {
      check_name=$1
      check_path=$(command -v "$check_name" 2>/dev/null) || return 0
      case "$seen" in *"|$check_path|"*) return 0 ;; esac
      seen="${seen}${check_path}|"
      found=1
      printf "%s\n" "-- $check_name ($check_path) --"
      "$check_path" -v 2>&1 | sed -n "1,3p"
    }
    for bin in php php-cgi php-fpm; do
      check_binary "$bin"
    done
    for version in 8.6 8.5 8.4 8.3 8.2 8.1 8.0 7.4 7.3 7.2 7.1 7.0 5.6; do
      check_binary "php$version"
      check_binary "php-fpm$version"
      check_binary "php$version-fpm"
      check_binary "php-cgi$version"
      check_binary "php$version-cgi"
    done
    if [ "$found" -eq 0 ]; then
      printf "%s\n" "No PHP executable found in the checked names."
    fi
  '; then
    printf 'ERROR: unable to query PHP runtime in %s (container may lack sh or exec permission).\n' "$target" >&2
    status=1
  fi
done

printf '\n%s\n' 'Note: this script checks process names and runs only version commands in exact containers supplied; it does not print process arguments, environment variables, or full inspect data.'
exit "$status"
