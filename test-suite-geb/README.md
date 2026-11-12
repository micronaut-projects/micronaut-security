By default, tests run using [Webdriver Testcontainers](https://www.testcontainers.org/modules/webdriver_containers/)

To run the [Geb](https://gebish.org) with [Firefox](https://www.mozilla.org/en-GB/firefox/) in your computer:

- [Download the Gecko driver for your OS](https://github.com/mozilla/geckodriver/releases).
- Run:
-
```
./gradlew :test-suite-geb:test
    -Dgeb.env=firefox
    -Dwebdriver.gecko.driver=/Users/sdelamo/Applications/geckodriver
```
