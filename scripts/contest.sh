#! /bin/sh -eu

ROOT=$(git rev-parse --show-toplevel)
RUNTIME=$1
shift

if [ "$RUNTIME" = "" ]; then
    echo "please specify runtime"
    exit 1
fi

if [ ! -e $RUNTIME ]; then
  if ! which $RUNTIME ; then
    echo "$RUNTIME not found"
    exit 1
  fi
fi

LOGFILE="${ROOT}/test.log"

if [ ! -f ${ROOT}/bundle.tar.gz ]; then
    cp ${ROOT}/tests/contest/contest/bundle.tar.gz ${ROOT}/bundle.tar.gz
fi
touch ${LOGFILE}

if [ $# -gt 0 ]; then
    ${ROOT}/contest run --runtime "$RUNTIME" --runtimetest "${ROOT}/runtimetest" -t "$@" 2>&1 | tee "$LOGFILE"
else
    ${ROOT}/contest run --runtime "$RUNTIME" --runtimetest "${ROOT}/runtimetest" 2>&1 | tee "$LOGFILE"
fi

if [ 0 -ne $(grep "not ok" $LOGFILE | wc -l ) ]; then
    exit 1
fi

echo "Validation successful for runtime $RUNTIME"
exit 0


