package io.micronaut.security.oauth2.docs

trait ConfigurationFixture {
    Map<String, Object> getConfiguration() {
        Map<String, Object> m = [:]
        if (specName) {
            m['spec.name'] = specName
        }
        m += loginHandlerCookieConfiguration
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

    Map<String, Object> getLoginHandlerCookieConfiguration() {
        ['micronaut.security.authentication': 'cookie'] as Map<String, Object>
    }

    Map<String, Object> getOauth2ClientConfiguration() {
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
