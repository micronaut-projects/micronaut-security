package io.micronaut.security.docs.jwtencryption

//tag::clazz[]
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMException
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.slf4j.LoggerFactory
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStreamReader
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Paths
import java.security.KeyPair
import java.security.Security
import java.util.Optional

object KeyPairProvider {
    private val LOG = LoggerFactory.getLogger(KeyPairProvider::class.java)

    /**
     * @param pemPath Full path to PEM file.
     * @return returns KeyPair if successfully for PEM files.
     */
    fun keyPair(pemPath: String): Optional<KeyPair> {
        // Load BouncyCastle as JCA provider
        Security.addProvider(BouncyCastleProvider())

        // Parse the EC key pair
        try {
            PEMParser(InputStreamReader(Files.newInputStream(Paths.get(pemPath)))).use { pemParser ->
                val pemKeyPair = pemParser.readObject() as PEMKeyPair

                // Convert to Java (JCA) format
                val converter = JcaPEMKeyConverter()
                val keyPair = converter.getKeyPair(pemKeyPair)

                return Optional.of(keyPair)
            }
        } catch (e: FileNotFoundException) {
            LOG.warn("file not found: {}", pemPath)
        } catch (e: NoSuchFileException) {
            LOG.warn("file not found: {}", pemPath)
        } catch (e: PEMException) {
            LOG.warn("PEMException {}", e.message)
        } catch (e: IOException) {
            LOG.warn("IOException {}", e.message)
        }
        return Optional.empty()
    }
}
//end::clazz[]
