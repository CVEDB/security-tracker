#!/bin/sh

set -eu

cd "$(dirname "$0")"

renice -n 20 -p $$ >/dev/null
ionice -c 3 -p $$

HOME=$PWD
export HOME

echo 'verbose = off' > .wgetrc
echo 'ca-certificate=/etc/ssl/ca-global/ca-certificates.crt' >> .wgetrc
output="$(./update.sh 2>&1)" || {
    es=$?
    echo "$output"
    exit $es
}

./lookup.sh | grep -v NOT-FOR-US
