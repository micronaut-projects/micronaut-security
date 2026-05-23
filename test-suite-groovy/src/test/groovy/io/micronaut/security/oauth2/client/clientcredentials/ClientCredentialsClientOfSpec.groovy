package io.micronaut.security.oauth2.client.clientcredentials

import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.keycloak.docker.Keycloak
import org.testcontainers.DockerClientFactory
import reactor.core.publisher.Mono
import spock.lang.Requires
import spock.lang.Specification

class ClientCredentialsClientOfSpec extends Specification {

    void cleanupSpec() {
        Keycloak.destroy()
    }

    @Requires({ DockerClientFactory.instance().isDockerAvailable() })
    void "it is possible to create a client credentials client without application context"() {
        given:
        String issuer = Keycloak.getIssuer()
        String clientId = Keycloak.CLIENT_ID
        String clientSecret = Keycloak.getClientSecret()
        HttpClient httpClient = HttpClient.create(new URL(issuer))

        when:
        String tokenUrl = tokenUrl(httpClient, issuer)

        then:
        tokenUrl != null

        when:
//tag::clientcredentialsof[]
        ClientCredentialsClient clientCredentialsClient = ClientCredentialsClient.of(httpClient,
                OauthClientConfiguration.builder()
                        .name("test")
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .token(tokenUrl)
                        .build())
//end::clientcredentialsof[]
        TokenResponse tokenResponse = Mono.from(clientCredentialsClient.requestToken()).block()

        then:
        tokenResponse != null
        tokenResponse.getAccessToken() != null

        when:
        TokenResponse newTokenResponse = Mono.from(clientCredentialsClient.requestToken()).block()

        then:
        newTokenResponse.getAccessToken() != null
        tokenResponse == newTokenResponse

        cleanup:
        httpClient.close()
    }

    private static String tokenUrl(HttpClient httpClient, String issuer) {
        DefaultOpenIdProviderMetadata openIdProviderMetadata = httpClient.toBlocking().retrieve(
                HttpRequest.GET(issuer + "/.well-known/openid-configuration"),
                Argument.of(DefaultOpenIdProviderMetadata))
        openIdProviderMetadata.getTokenEndpoint()
    }
}
