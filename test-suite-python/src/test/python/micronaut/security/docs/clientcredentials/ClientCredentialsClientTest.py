from typing import Annotated

import java
from jakarta.inject import Inject
from micronaut.context import ApplicationContext
from micronaut.context.annotation import Property
from micronaut.inject.qualifiers import Qualifiers
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test

from .MyClass import MyClass

# TODO(python): java.type needed because the imported Java interface is a wrapper that ApplicationContext.getBean()
# does not accept as the bean type ("Unsupported operation identifier 'getType' ... type: _MicronautJavaType")
ClientCredentialsClient = java.type("io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient")


@Property(name="spec.name", value="ClientCredentialsClientTest")
@Property(name="micronaut.security.oauth2.clients.companyauthserver.client-id", value="XXX")
@Property(name="micronaut.security.oauth2.clients.companyauthserver.client-secret", value="YYY")
@Property(name="micronaut.security.oauth2.clients.companyauthserver.token.url", value="https://foo.bar/token")
@Property(name="micronaut.security.oauth2.clients.companyauthserver.token.auth-method", value="client_secret_basic")
@Property(name="micronaut.security.oauth2.clients.google.client-id", value="ZZZZ")
@Property(name="micronaut.security.oauth2.clients.google.client-secret", value="PPPP")
@Property(name="micronaut.security.oauth2.clients.google.token.url", value="https://oauth2.googleapis.com/token")
@MicronautTest(startApplication=False)
class ClientCredentialsClientTest:
    myClass: Annotated[MyClass, Inject]
    beanContext: Annotated[ApplicationContext, Inject]

    @Test
    def test_client_credentials_clients_can_be_retrieved_by_name(self):
        assert self.myClass.google_client_credentials_client() is not None
        # tag::getBean[]
        client = self.beanContext.getBean(ClientCredentialsClient, Qualifiers.byName("companyauthserver"))
        # end::getBean[]
        assert client is not None
