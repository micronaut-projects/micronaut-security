# tag::clazz[]
from typing import Annotated

from com.nimbusds.jose import EncryptionMethod, JWEAlgorithm
from jakarta.inject import Named, Singleton
from java.security.interfaces import RSAPrivateKey, RSAPublicKey
from micronaut.context.annotation import Requires, Value
from micronaut.security.token.jwt.encryption.rsa import RSAEncryptionConfiguration

from .KeyPairProvider import KeyPairProvider
# end::clazz[]


@Requires(property="spec.name", value="RSAOAEPEncryptionTest")
# tag::clazz[]

@Named("generator")  # <1>
@Singleton
class RSAOAEPEncryptionConfiguration(RSAEncryptionConfiguration):

    def __init__(self, pemPath: Annotated[str, Value("${pem.path}")]):
        self.rsaPrivateKey = None
        self.rsaPublicKey = None
        self.jweAlgorithm = JWEAlgorithm.RSA_OAEP_256
        self.encryptionMethod = EncryptionMethod.A128GCM
        keyPair = KeyPairProvider.key_pair(pemPath)
        if keyPair.isPresent():
            self.rsaPublicKey = keyPair.get().getPublic()
            self.rsaPrivateKey = keyPair.get().getPrivate()

    def getPublicKey(self) -> RSAPublicKey:
        return self.rsaPublicKey

    def getPrivateKey(self) -> RSAPrivateKey:
        return self.rsaPrivateKey

    def getJweAlgorithm(self) -> JWEAlgorithm:
        return self.jweAlgorithm

    def getEncryptionMethod(self) -> EncryptionMethod:
        return self.encryptionMethod
# end::clazz[]
