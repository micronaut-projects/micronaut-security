package io.micronaut.security.oauth2

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
        m += loginModeCookie
        m += oauth2ClientConfiguration
        m
    }

    default boolean isUsingTestContainers() {
        !System.getProperty("geb.env") || System.getProperty("geb.env").contains('docker')
    }

    default String getOpenIdClientName() {
        'foo'
    }

    default String getSpecName() {
        null
    }

    default String getIssuer() {
        null
    }

    default Map<String, Object> getLoginModeCookie() {
        ['micronaut.security.authentication': 'cookie']
    }

    default Map<String, Object> getOauth2ClientConfiguration() {
        Map m = [
                ("micronaut.security.oauth2.clients.${openIdClientName}.client-id".toString()): 'XXXX',
                ("micronaut.security.oauth2.clients.${openIdClientName}.client-secret".toString()): 'YYYY',
        ]
        if (issuer != null) {
            m[("micronaut.security.oauth2.clients.${openIdClientName}.openid.issuer".toString())] = issuer
        }
        m
    }
}
