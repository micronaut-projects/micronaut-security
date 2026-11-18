package io.micronaut.security.oauth2.client

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.BeanInstantiationException
import io.micronaut.context.exceptions.ConfigurationException
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import spock.lang.Specification

class OpenIdProviderMetadataIssuerValidationSpec extends Specification {

    void "the issuer of the discovery document must match the configured issuer"() {
        given: 'an authorization server whose discovery document declares a different issuer'
        EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, ['spec.name': 'AuthServerOpenIdProviderMetadataIssuerValidationSpec'])
        int authServerPort = authServer.port
        String configuredIssuer = "http://localhost:${authServerPort}/oauth2/default"
        HttpClient httpClient = null
        EmbeddedServer server = null

        when: 'the application starts'
        server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                                           : 'OpenIdProviderMetadataIssuerValidationSpec',
                'micronaut.security.authentication'                   : 'cookie',
                'micronaut.security.oauth2.clients.okta.client-id'    : 'xxx',
                'micronaut.security.oauth2.clients.okta.client-secret': 'yyy',
                'micronaut.security.oauth2.clients.okta.openid.issuer': configuredIssuer,
        ])

        then: 'startup succeeds'
        server.running

        when: 'the provider metadata is used'
        server.applicationContext.getBean(DefaultOpenIdProviderMetadata, Qualifiers.byName('okta'))

        then: 'it fails with a message naming the provider and both issuers'
        BeanInstantiationException e = thrown()
        ConfigurationException cause = configurationException(e)
        cause != null
        cause.message.contains(MismatchingOpenIdConfigurationController.DISCOVERED_ISSUER)
        cause.message.contains(configuredIssuer)
        cause.message.contains('[okta]')
        cause.message.contains('micronaut.security.oauth2.clients.okta.openid.validate-issuer')
        cause.message.contains('micronaut.security.oauth2.clients.okta.openid.issuer-identifier')

        when: 'login is attempted'
        httpClient = server.applicationContext.createBean(HttpClient, server.URL, new DefaultHttpClientConfiguration(followRedirects: false))
        httpClient.toBlocking().exchange(HttpRequest.GET('/oauth/login/okta'))

        then: 'it fails in a controlled way'
        HttpClientResponseException ex = thrown()
        ex.status == HttpStatus.INTERNAL_SERVER_ERROR

        cleanup:
        httpClient?.close()
        server?.close()
        authServer.close()
    }

    void "issuer validation can be skipped with validate-issuer"() {
        given: 'an authorization server whose discovery document declares a different issuer'
        EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, ['spec.name': 'AuthServerOpenIdProviderMetadataIssuerValidationSpec'])
        int authServerPort = authServer.port
        HttpClient httpClient = null
        EmbeddedServer server = null

        when: 'the application starts with issuer validation disabled'
        server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                                                    : 'OpenIdProviderMetadataIssuerValidationSpec',
                'micronaut.security.authentication'                            : 'cookie',
                'micronaut.security.oauth2.clients.okta.client-id'             : 'xxx',
                'micronaut.security.oauth2.clients.okta.client-secret'         : 'yyy',
                'micronaut.security.oauth2.clients.okta.openid.issuer'         : "http://localhost:${authServerPort}/oauth2/default",
                'micronaut.security.oauth2.clients.okta.openid.validate-issuer': false,
        ])
        DefaultOpenIdProviderMetadata metadata = server.applicationContext.getBean(DefaultOpenIdProviderMetadata, Qualifiers.byName('okta'))

        then: 'the metadata resolves, and the announced issuer is still replaced by the configured one'
        metadata.issuer == "http://localhost:${authServerPort}/oauth2/default"
        metadata.jwksUri == MismatchingOpenIdConfigurationController.DISCOVERED_ISSUER + '/v1/keys'

        when: 'login is attempted'
        httpClient = server.applicationContext.createBean(HttpClient, server.URL, new DefaultHttpClientConfiguration(followRedirects: false))
        HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET('/oauth/login/okta'))

        then: 'it redirects to the provider'
        response.status == HttpStatus.FOUND
        response.header(HttpHeaders.LOCATION).startsWith(MismatchingOpenIdConfigurationController.DISCOVERED_ISSUER + '/v1/authorize')

        cleanup:
        httpClient?.close()
        server?.close()
        authServer.close()
    }

    private static ConfigurationException configurationException(Throwable t) {
        Throwable current = t
        while (current != null) {
            if (current instanceof ConfigurationException) {
                return (ConfigurationException) current
            }
            current = current.cause
        }
        null
    }

    @Requires(property = 'spec.name', value = 'AuthServerOpenIdProviderMetadataIssuerValidationSpec')
    @Controller('/oauth2/default/.well-known/openid-configuration')
    static class MismatchingOpenIdConfigurationController {
        static final String DISCOVERED_ISSUER = 'https://dev-133320.okta.com/oauth2/default'

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            '{"issuer":"' + DISCOVERED_ISSUER + '","authorization_endpoint":"' + DISCOVERED_ISSUER + '/v1/authorize","token_endpoint":"' + DISCOVERED_ISSUER + '/v1/token","jwks_uri":"' + DISCOVERED_ISSUER + '/v1/keys","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}'
        }
    }
}
