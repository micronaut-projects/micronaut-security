from typing import Annotated

from jakarta.inject import Inject
from micronaut.context.annotation import Property
from micronaut.security.authentication import UsernamePasswordCredentials
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test

from .PasswordAuthenticationProvider import PasswordAuthenticationProvider
from .UserStore import UserStore


@Property(name="spec.name", value="PasswordEncodingTest")
@MicronautTest(startApplication=False)
class PasswordEncodingTest:
    userStore: Annotated[UserStore, Inject]
    authenticationProvider: Annotated[PasswordAuthenticationProvider, Inject]

    @Test
    def test_authenticates_against_the_encoded_password(self):
        self.userStore.register("sherlock", "elementary")

        assert self.userStore.find_encoded_password("sherlock").startswith("$argon2id$v=19$")
        assert self.authenticate("sherlock", "elementary").isAuthenticated()
        assert not self.authenticate("sherlock", "wrong").isAuthenticated()
        assert not self.authenticate("watson", "elementary").isAuthenticated()

    def authenticate(self, username: str, password: str):
        return self.authenticationProvider.authenticate(None, UsernamePasswordCredentials(username, password))
