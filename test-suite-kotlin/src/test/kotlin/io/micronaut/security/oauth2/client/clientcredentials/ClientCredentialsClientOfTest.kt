package io.micronaut.security.oauth2.client.clientcredentials

import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationBuilder
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.keycloak.docker.Keycloak
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.testcontainers.junit.jupiter.Testcontainers
import reactor.core.publisher.Mono
import java.net.URI

@Testcontainers(disabledWithoutDocker = true)
internal class ClientCredentialsClientOfTest {

    @Test
    fun itIsPossibleToCreateAClientCredentialsClientWithoutApplicationContext() {
        val issuer = Keycloak.getIssuer()
        val clientId = Keycloak.CLIENT_ID
        val clientSecret = Keycloak.getClientSecret()
        val httpClient = HttpClient.create(URI.create(issuer).toURL())
        try {
            val tokenUrl = tokenUrl(httpClient, issuer)
            Assertions.assertNotNull(tokenUrl)
//tag::clientcredentialsof[]
            val clientCredentialsClient = ClientCredentialsClient.of(
                httpClient,
                OauthClientConfigurationBuilder.builder()
                    .name("test")
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .token(tokenUrl)
                    .build()
            )
//end::clientcredentialsof[]
            val tokenResponse: TokenResponse? = Mono.from(clientCredentialsClient.requestToken()).block()
            Assertions.assertNotNull(tokenResponse)
            Assertions.assertNotNull(tokenResponse!!.accessToken)

            val newTokenResponse: TokenResponse? = Mono.from(clientCredentialsClient.requestToken()).block()
            val assertedNewTokenResponse = Assertions.assertNotNull(newTokenResponse)
            Assertions.assertNotNull(assertedNewTokenResponse.accessToken)
            Assertions.assertEquals(tokenResponse, newTokenResponse)
        } finally {
            httpClient.close()
        }
    }

    companion object {
        @AfterAll
        @JvmStatic
        fun cleanupSpec() {
            Keycloak.destroy()
        }

        private fun tokenUrl(httpClient: HttpClient, issuer: String): String {
            val openIdProviderMetadata = httpClient.toBlocking().retrieve(
                HttpRequest.GET<Any>("$issuer/.well-known/openid-configuration"),
                Argument.of(DefaultOpenIdProviderMetadata::class.java)
            )
            return openIdProviderMetadata.tokenEndpoint
        }
    }
}
