#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/../verification" && ./build_and_verify.sh
