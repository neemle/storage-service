#!/bin/sh
set -e

IGNORE_IDS=""
if [ -f audit.toml ]; then
  IGNORE_IDS=$(awk -F'"' '/RUSTSEC-[0-9-]+/ {for (i=2; i<=NF; i+=2) if ($i ~ /^RUSTSEC-/) print $i}' audit.toml)
fi

set -- cargo audit
for advisory in $IGNORE_IDS; do
  set -- "$@" --ignore "$advisory"
done

"$@"
