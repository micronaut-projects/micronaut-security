package io.micronaut.security.oauth2

trait ConfigurationFixture {
    Map<String, Object> getConfiguration() {
        Map<String, Object> m = [:]
        if (specName) {
            m['spec.name'] = specName
        }
        m += loginModeCookie
        m += oauth2ClientConfiguration
        m
    }

    String getOpenIdClientName() {
        'foo'
    }

    String getSpecName() {
        null
    }

    String getIssuer() {
        null
    }

    Map<String, Object> getLoginModeCookie() {
        ['micronaut.security.authentication': 'cookie']
    }

    Map<String, Object> getOauth2ClientConfiguration() {
        Map<String, Object> m = [:]
        if (clientId) {
           m["micronaut.security.oauth2.clients.${openIdClientName}.client-id".toString()] = clientId
        }
        if (clientSecret) {
            m["micronaut.security.oauth2.clients.${openIdClientName}.client-secret".toString()] = 'YYYY'
        }
        if (issuer != null) {
            m[("micronaut.security.oauth2.clients.${openIdClientName}.openid.issuer".toString())] = issuer
        }
        m
    }

    String getClientId() {
        'XXXX'
    }

    String getClientSecret() {
        'YYYY'
    }
}
