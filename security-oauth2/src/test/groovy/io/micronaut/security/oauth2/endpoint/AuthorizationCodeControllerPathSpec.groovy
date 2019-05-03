package io.micronaut.security.oauth2.endpoint

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.endpoints.token.request.TokenEndpointClient
import io.micronaut.security.oauth2.openid.endpoints.token.TokenEndpoint
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class AuthorizationCodeControllerPathSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            (SPEC_NAME_PROPERTY): getClass().simpleName,
            'micronaut.security.enabled': true,
            'micronaut.security.token.jwt.enabled': true,
            'micronaut.security.oauth2.client-id': 'XXX',
            'micronaut.security.oauth2.token.redirect-uri': 'http://localhost:8080',
            'micronaut.security.oauth2.token.url': 'http://localhost:8080',
            'micronaut.security.endpoints.authcode.controller-path': '/cb',
            'micronaut.security.endpoints.authcode.action-path': '/',


    ], Environment.TEST)

    @Shared
    @AutoCleanup
    RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())

    @Unroll
    void "#clazz bean is available"() {
        expect:
        embeddedServer.applicationContext.containsBean(clazz)

        where:
        clazz << [
                OauthClientConfiguration,
                OpenIdProviderMetadata,
                TokenEndpoint,
                TokenEndpointClient,
                AuthorizationCodeController
        ]
    }


    void "AuthorizationCodeController is no longer accessible at /authcode/cb"() {
        when:
        client.toBlocking().exchange(HttpRequest.GET('/authcode/cb'))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "AuthorizationCodeController is accessible at /cb"() {
        expect:
        embeddedServer.applicationContext.containsBean(AuthorizationCodeController)

        when:
        client.toBlocking().exchange(HttpRequest.GET('/cb'))

        then:
        noExceptionThrown()
    }

}
