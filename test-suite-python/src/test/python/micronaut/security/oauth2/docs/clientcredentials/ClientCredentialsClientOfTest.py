from java.net import URL
from micronaut.core.type import Argument
from micronaut.http import HttpRequest
from micronaut.http.client import HttpClient
from micronaut.security.oauth2.client import DefaultOpenIdProviderMetadata
from micronaut.security.oauth2.client.clientcredentials import ClientCredentialsClient
from micronaut.security.oauth2.configuration import OauthClientConfiguration
from micronaut.security.oauth2.keycloak.docker import Keycloak
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import AfterAll, Assumptions, Test
from org.testcontainers import DockerClientFactory
from reactor.core.publisher import Mono


# Python tests need the GraalPy runtime of a Micronaut context, so the test uses @MicronautTest without
# starting an application; the ClientCredentialsClient itself is created without an application context.
@MicronautTest(startApplication=False)
class ClientCredentialsClientOfTest:

    @AfterAll
    @staticmethod
    def cleanupSpec() -> None:
        Keycloak.destroy()

    @Test
    def test_it_is_possible_to_create_a_client_credentials_client_without_application_context(self):
        Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable(), "Docker is not available")
        issuer = Keycloak.getIssuer()
        clientId = Keycloak.CLIENT_ID
        clientSecret = Keycloak.getClientSecret()
        httpClient = HttpClient.create(URL(issuer))
        try:
            tokenUrl = self.token_url(httpClient, issuer)
            assert tokenUrl is not None
# tag::clientcredentialsof[]
            clientCredentialsClient = ClientCredentialsClient.of(
                httpClient,
                OauthClientConfiguration.builder().name("test")
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .token(tokenUrl)
                    .build(),
            )
# end::clientcredentialsof[]
            # Request a token
            tokenResponse = Mono.from_(clientCredentialsClient.requestToken()).block()
            assert tokenResponse is not None
            assert tokenResponse.getAccessToken() is not None

            # Request a token again.
            newTokenResponse = Mono.from_(clientCredentialsClient.requestToken()).block()
            assert newTokenResponse is not None
            assert newTokenResponse.getAccessToken() is not None
            # Token is cached
            assert tokenResponse.equals(newTokenResponse)
        finally:
            httpClient.close()

    def token_url(self, httpClient: HttpClient, issuer: str) -> str:
        client = httpClient.toBlocking()
        openIdProviderMetadata = client.retrieve(
            HttpRequest.GET(issuer + "/.well-known/openid-configuration"),
            Argument.of(DefaultOpenIdProviderMetadata),
        )
        return openIdProviderMetadata.getTokenEndpoint()
