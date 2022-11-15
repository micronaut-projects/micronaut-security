#!/usr/bin/env bash

set -e

EXIT_STATUS=0

attempt_counter=0
max_attempts=5

# generate Auth server ShadowJAR
./gradlew test-suite-aot-authserver:shadowJar> /dev/null

# run this in the background
java -jar test-suite-aot-authserver/build/libs/authserver.jar > /dev/null &
AUTH_PID=$!

until $(curl --output /dev/null --silent --head --fail http://localhost:8081/health); do
    if [ ${attempt_counter} -eq ${max_attempts} ];then
      echo "Max attempts reached"
       killall -9 java
      exit 1
    fi
    attempt_counter=$(($attempt_counter+1))
    sleep 5
done

# run this to avoid any gradle caching of the optimizations
./gradlew :test-suite-aot:clean > /dev/null || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  killall -9 java
  exit $EXIT_STATUS
fi

./gradlew :test-suite-aot:optimizedJitJarAll > /dev/null || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  killall -9 java
  exit $EXIT_STATUS
fi

# kill auth server. Optimized JAR will work even if auth server is down
killall -9 java

java -jar test-suite-aot/build/libs/test-suite-aot-0.1-all-optimized.jar > /dev/null &
OPTIMIZED_RUN_PID=$!

echo "optimized JIT JAR pid $OPTIMIZED_RUN_PID"

until $(curl --output /dev/null --silent --head --fail http://localhost:8080); do
    if [ ${attempt_counter} -eq ${max_attempts} ];then
      echo "Max attempts reached"
      killall -9 java
      exit 1
    fi
    attempt_counter=$(($attempt_counter+1))
    sleep 5
done

killall -9 java

exit $EXIT_STATUS








