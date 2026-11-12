package io.micronaut.security.testutils

import groovy.transform.CompileStatic

@CompileStatic
class ConfigurationUtils {
    static Map<String, Object> getConfiguration(String specName,
                                                String authenticationMode = 'cookie',
                                                String openIdClientName = 'foo',
                                                String issuer = null) {
        Map<String, Object> m = [:]
        if (specName) {
            m['spec.name'] = specName
        }
        m['micronaut.security.authentication'] = authenticationMode
        m += getOauth2ClientConfiguration(openIdClientName, issuer)
        m
    }

    private static Map<String, Object> getOauth2ClientConfiguration(String openIdClientName, String issuer) {
        Map<String, Object> m = [
                ("micronaut.security.oauth2.clients.${openIdClientName}.client-id".toString()): 'XXXX',
                ("micronaut.security.oauth2.clients.${openIdClientName}.client-secret".toString()): 'YYYY',
        ] as Map<String, Object>
        if (issuer != null) {
            m[("micronaut.security.oauth2.clients.${openIdClientName}.openid.issuer".toString())] = issuer
        }
        m
    }
}
