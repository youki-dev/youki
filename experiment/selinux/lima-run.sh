#!/bin/bash

set -eu -o pipefail

limactl shell --workdir /workdir/youki/experiment/selinux youki-selinux "$@"
