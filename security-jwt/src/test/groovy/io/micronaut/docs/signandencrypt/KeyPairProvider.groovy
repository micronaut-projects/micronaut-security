package io.micronaut.docs.signandencrypt

import groovy.util.logging.Slf4j
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMException
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter

import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyPair
import java.security.Security

//tag::clazz[]
@Slf4j
class KeyPairProvider {
    /**
     *
     * @param pemPath Full path to PEM file.
     * @return returns KeyPair if successfully for PEM files.
     */
    static Optional<KeyPair> keyPair(String pemPath) {
        // Load BouncyCastle as JCA provider
        Security.addProvider(new BouncyCastleProvider())

        // Parse the EC key pair
        PEMParser pemParser
        try {
            pemParser = new PEMParser(new InputStreamReader(Files.newInputStream(Paths.get(pemPath))))
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject()

            // Convert to Java (JCA) format
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
            KeyPair keyPair = converter.getKeyPair(pemKeyPair)
            pemParser.close()

            return Optional.of(keyPair)

        } catch (FileNotFoundException e) {
            log.warn("file not found: {}", pemPath)

        } catch (PEMException e) {
            log.warn("PEMException {}", e.getMessage())

        } catch (IOException e) {
            log.warn("IOException {}", e.getMessage())
        }
        return Optional.empty()
    }
}
//end::clazz[]
