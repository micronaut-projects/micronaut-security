from typing import Annotated

from jakarta.inject import Named, Singleton
from micronaut.context.annotation import Requires
from micronaut.security.oauth2.client.clientcredentials import ClientCredentialsClient


@Requires(property="spec.name", value="ClientCredentialsClientTest")
@Singleton
class MyClass:
# tag::constructor[]
    def __init__(self, googleClientCredentialsClient: Annotated[ClientCredentialsClient, Named("google")]):
        self.googleClientCredentialsClient = googleClientCredentialsClient
# end::constructor[]

    def google_client_credentials_client(self) -> ClientCredentialsClient:
        return self.googleClientCredentialsClient
