from typing import Annotated

import java
from com.nimbusds.jwt import EncryptedJWT, JWTParser
from jakarta.inject import Inject, Named
from micronaut.context.annotation import Property
from micronaut.security.authentication import Authentication
from micronaut.security.token.generator import TokenGenerator
from micronaut.security.token.jwt.encryption import EncryptionConfiguration
from micronaut.security.token.jwt.encryption.rsa import RSAEncryption
from micronaut.security.token.validator import TokenValidator
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test
from reactor.core.publisher import Mono


@Property(name="spec.name", value="RSAOAEPEncryptionTest")
@Property(name="pem.path", value="src/test/resources/rsa-2048bit-key-pair.pem")
@Property(name="micronaut.security.token.jwt.signatures.secret.generator.secret", value="pleaseChangeThisSecretForANewOne")
@MicronautTest(startApplication=False)
class RSAOAEPEncryptionTest:
    encryptionConfiguration: Annotated[EncryptionConfiguration, Inject, Named("generator")]
    tokenGenerator: Annotated[TokenGenerator, Inject]
    tokenValidator: Annotated[TokenValidator, Inject]

    @Test
    def test_tokens_are_encrypted_with_the_rsa_key_pair(self):
        assert java.instanceof(self.encryptionConfiguration, RSAEncryption)
        token = self.tokenGenerator.generateToken(Authentication.build("sherlock"), 3600)
        assert token.isPresent()
        assert java.instanceof(JWTParser.parse(token.get()), EncryptedJWT)
        authentication = Mono.from_(self.tokenValidator.validateToken(token.get(), None)).block()
        assert authentication is not None
        assert authentication.getName() == "sherlock"
