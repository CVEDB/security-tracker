#!/bin/sh

set -eu

empty=true

input="$(cat)"
if [ -n "$input" ]; then
    empty=false
fi

if ! $empty; then
    echo "$input"
    cat "$1"
fi
