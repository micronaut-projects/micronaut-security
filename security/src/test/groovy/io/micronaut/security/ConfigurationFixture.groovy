package io.micronaut.security

interface ConfigurationFixture {

    default Map<String, Object> getConfiguration() {
        Map<String, Object> m = [:]
        if (specName) {
            m['spec.name'] = specName
        }
        if (isUsingTestContainers()) {
            m['micronaut.security.token.jwt.cookie.cookie-secure'] = false
            m['micronaut.security.token.refresh.cookie.cookie-secure'] = false
        }
        m
    }

    default boolean isUsingTestContainers() {
        !System.getProperty("geb.env") || System.getProperty("geb.env").contains('docker')
    }

    default String getSpecName() {
        null
    }
}