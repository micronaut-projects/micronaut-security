# tag::clazz[]
import logging

from java.io import InputStreamReader
from java.nio.file import Files, Paths
from java.security import Security
from java.util import Optional
from org.bouncycastle.jce.provider import BouncyCastleProvider
from org.bouncycastle.openssl import PEMParser
from org.bouncycastle.openssl.jcajce import JcaPEMKeyConverter

LOG = logging.getLogger(__name__)


class KeyPairProvider:

    @staticmethod
    def key_pair(pemPath: str) -> Optional:
        """
        :param pemPath: Full path to PEM file.
        :return: returns KeyPair if successfully for PEM files.
        """
        # Load BouncyCastle as JCA provider
        Security.addProvider(BouncyCastleProvider())

        # Parse the EC key pair
        try:
            pemParser = PEMParser(InputStreamReader(Files.newInputStream(Paths.get(pemPath))))
            try:
                pemKeyPair = pemParser.readObject()

                # Convert to Java (JCA) format
                converter = JcaPEMKeyConverter()
                keyPair = converter.getKeyPair(pemKeyPair)

                return Optional.of(keyPair)
            finally:
                pemParser.close()
        except Exception as e:
            LOG.warning("could not read the key pair from %s: %s", pemPath, e)
        return Optional.empty()
# end::clazz[]
