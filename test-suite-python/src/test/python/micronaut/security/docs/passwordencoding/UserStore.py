from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.security.password import PasswordEncoder


@Requires(property="spec.name", value="PasswordEncodingTest")
# tag::clazz[]
@Singleton
class UserStore:

    def __init__(self, passwordEncoder: PasswordEncoder):
        self.passwordEncoder = passwordEncoder
        self.encodedPasswords = {}

    def register(self, username: str, rawPassword: str) -> None:
        self.encodedPasswords[username] = self.passwordEncoder.encode(rawPassword)  # <1>

    def find_encoded_password(self, username: str) -> str | None:
        return self.encodedPasswords.get(username)
# end::clazz[]
