#!/usr/bin/env bash

#set -xe
#set -e
EXIT_STATUS=0

DELAY=30

#exiting() {
#  kill -9 $AUTH_PID
#  kill -9 $OPTIMIZED_RUN_PID
#}
#trap exiting EXIT

execute() {
  local END=$((SECONDS+DELAY))
  CURLCMD=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080")
  echo "curling $CURLCMD"
  while [ "$CURLCMD" != "200" ]; do
    echo "curling $CURLCMD"
    if [ $SECONDS -gt $END ]; then
      echo "No response from the app in $DELAY seconds" >&2
      exit 1
    fi
    sleep 0.001;
    CURLCMD=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080")
  done
}

# run this in the background
./gradlew test-suite-aot-auth-a:run > /dev/null &
AUTH_PID=$!

# run this to avoid any gradle caching of the optimizations
./gradlew :test-suite-aot:clean || EXIT_STATUS=$?

# run this to in the background
./gradlew :test-suite-aot:optimizedRun > /dev/null &
OPTIMIZED_RUN_PID=$!

# stop the auth server
kill -9 $AUTH_PID

execute || EXIT_STATUS=$?
if [ $EXIT_STATUS -ne 0 ]; then
  exit $EXIT_STATUS
fi

# stop the optimized run
kill -9 $OPTIMIZED_RUN_PID

exit $EXIT_STATUS








