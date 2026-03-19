#!/bin/bash

EXIT_STATUS=0

for ((i=1; i<=100; i++))
do
  ./gradlew :micronaut-security:test --tests "io.micronaut.security.token.TokenAuthenticationFetcherSpec.Beans of type TokenReader are evaluated in order" --rerun-tasks || EXIT_STATUS=$?
  if [ $EXIT_STATUS -ne 0 ]; then
    exit $EXIT_STATUS
  fi
done

exit $EXIT_STATUS
