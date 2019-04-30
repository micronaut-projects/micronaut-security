package io.micronaut.security.oauth2.endpoint

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.RxHttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.authorization.response.Oauth2AuthorizationResponseHandler

import io.micronaut.security.oauth2.handlers.IdTokenAccessTokenResponseHandler
import io.micronaut.security.oauth2.handlers.SuccessfulIdTokenAccessTokenResponseHandler
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderMetadata
import io.micronaut.security.oauth2.state.StateSerDes
import io.micronaut.security.oauth2.endpoints.token.request.TokenEndpointClient
import io.micronaut.security.oauth2.endpoints.token.request.OpenIdTokenEndpointClient
import io.micronaut.security.oauth2.openid.endpoints.token.TokenEndpoint
import io.micronaut.security.oauth2.endpoint.token.response.validation.OpenIdTokenResponseValidator
import io.micronaut.security.oauth2.responses.Oauth2AuthenticationResponse
import spock.lang.Specification

class AuthorizationCodeControllerSpec extends Specification {

    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "Authorization Code Grant Flow"() {
        given:
        int mockHttpServerPort = SocketUtils.findAvailableTcpPort()
        EmbeddedServer mockHttpServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY): 'authorizationcodecontrollerspecmockhttpserver',
                'micronaut.server.port': mockHttpServerPort,
                'micronaut.security.enabled': true,
        ])

        expect:
        mockHttpServer.applicationContext.containsBean(MockTokenEndpointController)

        when:
        String path = '/oauth2/default/v1/token'
        HttpClient mockHttpClient = HttpClient.create(mockHttpServer.URL)
        HttpResponse rsp = mockHttpClient.toBlocking().exchange(HttpRequest.POST(path, ""))

        then:
        rsp.status() == HttpStatus.OK

        when:
        String mockHttpServerUrl = "http://localhost:${mockHttpServerPort}"
        String authorizationRedirectUri = "${mockHttpServerUrl}/authcode/cb"
        String tokenEndpointUrl = "${mockHttpServerUrl}${path}"
        Map<String, Object> config = [
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.enabled': true,
                'micronaut.security.token.jwt.enabled': true,
                'micronaut.security.oauth2.client-id': 'XXX',
                'micronaut.security.oauth2.token.auth-method': '',
                'micronaut.security.oauth2.token.content-type': 'application/json',
                'micronaut.security.oauth2.authorization.redirect-uri': authorizationRedirectUri,
                'micronaut.security.oauth2.token.redirect-uri': authorizationRedirectUri,
                'micronaut.security.oauth2.token.url': tokenEndpointUrl,
                'micronaut.security.oauth2.openid.idtoken.cookie.enabled': false

        ]
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config, Environment.TEST)

        then:
        embeddedServer.applicationContext.containsBean(OauthClientConfiguration)

        and:
        embeddedServer.applicationContext.containsBean(OpenIdProviderMetadata)

        and:
        embeddedServer.applicationContext.containsBean(AuthorizationCodeController)

        when:
        TokenEndpoint tokenEndpoint = embeddedServer.applicationContext.getBean(TokenEndpoint)

        then:
        noExceptionThrown()
        tokenEndpoint.getRedirectUri() != null

        and:
        embeddedServer.applicationContext.containsBean(TokenEndpointClient)

        and:
        embeddedServer.applicationContext.containsBean(OpenIdTokenEndpointClient)

        and:
        embeddedServer.applicationContext.containsBean(SuccessfulIdTokenAccessTokenResponseHandler)

        and:
        embeddedServer.applicationContext.containsBean(OpenIdTokenResponseValidator)

        and:
        embeddedServer.applicationContext.containsBean(IdTokenAccessTokenResponseHandler)

        and:
        embeddedServer.applicationContext.containsBean(Oauth2AuthorizationResponseHandler)

        and:
        embeddedServer.applicationContext.containsBean(AuthorizationCodeController)

        when:
        RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())
        Oauth2AuthenticationResponse authenticationResponse = new Oauth2AuthenticationResponse(embeddedServer.applicationContext.getBean(StateSerDes))
        authenticationResponse.setCode("SplxlOBeZQQYbYS6WxSbIA")
        authenticationResponse.setState("af0ifjsldkj")
        HttpRequest request = HttpRequest.POST('/authcode/cb', authenticationResponse)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        rsp = client.toBlocking().exchange(request)

        then:
        rsp.status() == HttpStatus.OK

        cleanup:
        mockHttpClient.close()
        mockHttpServer.close()
        client.close()
        embeddedServer.close()
    }
}
