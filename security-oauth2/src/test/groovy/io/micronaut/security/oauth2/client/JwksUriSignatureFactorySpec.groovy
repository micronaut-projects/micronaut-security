package io.micronaut.security.oauth2.client

import io.micronaut.context.ApplicationContext
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher
import spock.lang.Issue
import spock.lang.Specification

class JwksUriSignatureFactorySpec extends Specification {

    @Issue("https://github.com/micronaut-projects/micronaut-security/issues/2366")
    void "OIDC JWKS metadata can coexist with explicit JWKS configuration of the same name"() {
        given:
        ApplicationContext context = ApplicationContext.builder()
                .properties([
                        'micronaut.security.token.jwt.signatures.jwks.keycloak.url': 'https://example.org/jwks'
                ])
                .start()
        DefaultOpenIdProviderMetadata metadata = new DefaultOpenIdProviderMetadata('keycloak')
        metadata.setJwksUri('https://example.org/oidc-jwks')
        context.registerSingleton(DefaultOpenIdProviderMetadata, metadata, Qualifiers.byName('keycloak'), true)

        when:
        context.getBean(JwkSetFetcher)

        then:
        noExceptionThrown()
        context.getBeansOfType(JwksSignatureConfiguration).size() == 1
        context.getBean(JwksSignatureConfiguration, Qualifiers.byName('keycloak')).url == 'https://example.org/jwks'

        cleanup:
        context?.close()
    }

    void "OIDC JWKS metadata creates a configuration when no explicit configuration exists"() {
        given:
        ApplicationContext context = ApplicationContext.builder().start()
        DefaultOpenIdProviderMetadata metadata = new DefaultOpenIdProviderMetadata('keycloak')
        metadata.setJwksUri('https://example.org/oidc-jwks')
        context.registerSingleton(DefaultOpenIdProviderMetadata, metadata, Qualifiers.byName('keycloak'), true)

        when:
        context.getBean(JwkSetFetcher)

        then:
        noExceptionThrown()
        context.getBeansOfType(JwksSignatureConfiguration).size() == 1
        context.getBean(JwksSignatureConfiguration, Qualifiers.byName('keycloak')).url == 'https://example.org/oidc-jwks'

        cleanup:
        context?.close()
    }
}
