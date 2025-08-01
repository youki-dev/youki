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

# TODO: This is a temporary change to exclude net_devices test for non-youki runtimes
# This should be removed once the net_devices test is fixed for other runtimes
if [ "$(basename "$RUNTIME")" != "youki" ]; then
    TEST_LIST=$(${ROOT}/contest list | grep -v "net_devices" | grep -v " " | tr '\n' ' ')
else
    TEST_LIST=$(${ROOT}/contest list | grep -v " " | tr '\n' ' ')
fi

if [ $# -gt 0 ]; then
    ${ROOT}/contest run --runtime "$RUNTIME" --runtimetest "${ROOT}/runtimetest" -t "$@" > "$LOGFILE"
else
    ${ROOT}/contest run --runtime "$RUNTIME" --runtimetest "${ROOT}/runtimetest" -t $TEST_LIST > "$LOGFILE"
fi

if [ 0 -ne $(grep "not ok" $LOGFILE | wc -l ) ]; then
    cat $LOGFILE
    exit 1
fi

echo "Validation successful for runtime $RUNTIME"
exit 0


