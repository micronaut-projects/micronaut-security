package io.micronaut.security.oauth2.client

import io.micronaut.context.ApplicationContext
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher
import io.micronaut.context.exceptions.BeanInstantiationException
import spock.lang.Issue
import spock.lang.Specification

class JwksUriSignatureFactorySpec extends Specification {

    @Issue("https://github.com/micronaut-projects/micronaut-security/issues/2366")
    void "same OIDC and explicit JWKS URL does not create duplicate configuration"() {
        given:
        String jwksUrl = 'https://example.org/jwks'
        ApplicationContext context = ApplicationContext.builder()
                .properties([
                        'micronaut.security.oauth2.clients.keycloak.openid.issuer': 'https://example.org/issuer',
                        'micronaut.security.oauth2.clients.keycloak.openid.fetch-configuration': 'false',
                        'micronaut.security.oauth2.clients.keycloak.openid.jwks-uri': jwksUrl,
                        'micronaut.security.token.jwt.signatures.jwks.keycloak.url': jwksUrl
                ])
                .start()

        when:
        context.getBean(JwkSetFetcher)

        then:
        noExceptionThrown()
        context.getBeansOfType(JwksSignatureConfiguration).size() == 1
        context.getBean(JwksSignatureConfiguration, Qualifiers.byName('keycloak')).url == jwksUrl

        cleanup:
        context?.close()
    }

    void "different OIDC and explicit JWKS URLs with the same name fail"() {
        given:
        ApplicationContext context = ApplicationContext.builder()
                .properties([
                        'micronaut.security.oauth2.clients.keycloak.openid.issuer': 'https://example.org/issuer',
                        'micronaut.security.oauth2.clients.keycloak.openid.fetch-configuration': 'false',
                        'micronaut.security.oauth2.clients.keycloak.openid.jwks-uri': 'https://example.org/oidc-jwks',
                        'micronaut.security.token.jwt.signatures.jwks.keycloak.url': 'https://example.org/explicit-jwks'
                ])
                .start()

        when:
        context.getBean(JwkSetFetcher)

        then:
        BeanInstantiationException e = thrown()
        e.message.contains('Duplicate key keycloak')

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
