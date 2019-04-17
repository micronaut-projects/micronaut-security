package io.micronaut.security.oauth2.grants.password.passwordflow

import io.micronaut.context.ApplicationContext
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.grants.password.GrantTypePasswordAuthenticationProvider
import io.micronaut.security.oauth2.openid.configuration.OpenIdConfigurationClient
import spock.lang.Specification

class PasswordFlowSpec extends Specification {

    def "verify password flow"() {
        setup:
        int mockHttpServerPort = SocketUtils.findAvailableTcpPort()
        String mockHttpServerUrl = "http://localhost:${mockHttpServerPort}"
        Map<String, Object> mockHttpServerConf = [
                'spec.name': 'passwordFlowMockHttpServer',
                'micronaut.security.enabled': true,
                'micronaut.server.port': mockHttpServerPort,
                'mockserver.url': mockHttpServerUrl
        ]
        EmbeddedServer mockHttpServer = ApplicationContext.run(EmbeddedServer, mockHttpServerConf)

        expect:
        mockHttpServer.applicationContext.containsBean(Oauth2Controller)
        mockHttpServer.applicationContext.containsBean(OpenIdConfigurationController)

        when:
        HttpClient mockHttpClient = mockHttpServer.applicationContext.createBean(HttpClient, mockHttpServer.URL)

        String openidConfigurationEndpointUri = "${mockHttpServerUrl}/.well-known/openid-configuration".toString()

        HttpRequest openidConfigurationReq = HttpRequest.GET(openidConfigurationEndpointUri)
        HttpResponse<String> rsp = mockHttpClient.toBlocking().exchange(openidConfigurationReq, String)

        then:
        noExceptionThrown()
        rsp.status() == HttpStatus.OK
        rsp.body() != null

        when:
        Map<String, Object> conf = [
                'spec.name': 'passwordFlow',
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.client-id': 'XXXX',
                'micronaut.security.oauth2.client-secret': 'YYYY',
                'micronaut.security.oauth2.openid.issuer': mockHttpServerUrl,
                "micronaut.security.oauth2.grant-type-password.enabled": true
        ]
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, conf)
        String issuer = server.applicationContext.getProperty("micronaut.security.oauth2.openid.issuer", String)

        then:
        issuer

        when:
        OpenIdConfigurationClient openIdConfigurationClient = server.applicationContext.getBean(OpenIdConfigurationClient)

        then:
        openIdConfigurationClient
        openIdConfigurationClient.fetchConfiguration()

        and:
        server.applicationContext.containsBean(EchoUserNameController)

        and:
        server.applicationContext.containsBean(DefaultIdTokenAccessTokenResponseValidatorReplacement)

        and:
        server.applicationContext.containsBean(GrantTypePasswordAuthenticationProvider)

        when:
        HttpClient httpClient = HttpClient.create(server.URL)
        HttpRequest request = HttpRequest.GET("/echo").basicAuth("john", "secret")
        String username = httpClient.toBlocking().retrieve(request, String)

        then:
        username == 'john'

        cleanup:
        httpClient.close()

        and:
        server.close()

        and:
        mockHttpServer.close()

        and:
        mockHttpClient.close()
    }

}
