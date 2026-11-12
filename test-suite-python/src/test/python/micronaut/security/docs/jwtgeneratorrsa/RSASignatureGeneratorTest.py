from typing import Annotated

import java
from com.nimbusds.jose import JWSAlgorithm
from com.nimbusds.jwt import SignedJWT
from jakarta.inject import Inject, Named, Singleton
from java.security import KeyPairGenerator
from micronaut.context.annotation import Property, Requires
from micronaut.security.authentication import Authentication
from micronaut.security.token.generator import TokenGenerator
from micronaut.security.token.jwt.signature import SignatureGeneratorConfiguration
from micronaut.security.token.jwt.signature.rsa import RSASignatureGenerator, RSASignatureGeneratorConfiguration
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="RSASignatureGeneratorTest")
@MicronautTest(startApplication=False)
class RSASignatureGeneratorTest:
    signatureGeneratorConfiguration: Annotated[SignatureGeneratorConfiguration, Inject, Named("generator")]
    tokenGenerator: Annotated[TokenGenerator, Inject]

    @Test
    def test_tokens_are_signed_with_the_rsa_signature_generator(self):
        assert java.instanceof(self.signatureGeneratorConfiguration, RSASignatureGenerator)
        token = self.tokenGenerator.generateToken(Authentication.build("sherlock"), 3600)
        assert token.isPresent()
        jwt = SignedJWT.parse(token.get())
        assert jwt.getHeader().getAlgorithm() == JWSAlgorithm.RS256
        assert jwt.getJWTClaimsSet().getSubject() == "sherlock"


@Requires(property="spec.name", value="RSASignatureGeneratorTest")
@Singleton
class MyRSASignatureGeneratorConfiguration(RSASignatureGeneratorConfiguration):

    def __init__(self):
        keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        self.keyPair = keyPairGenerator.generateKeyPair()

    def getPrivateKey(self):
        return self.keyPair.getPrivate()

    def getJwsAlgorithm(self):
        return JWSAlgorithm.RS256

    def getPublicKey(self):
        return self.keyPair.getPublic()
