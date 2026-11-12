package io.micronaut.security.docs.jwtencryption;

//tag::clazz[]
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.util.Optional;

public class KeyPairProvider {
    private static final Logger LOG = LoggerFactory.getLogger(KeyPairProvider.class);

    /**
     * @param pemPath Full path to PEM file.
     * @return returns KeyPair if successfully for PEM files.
     */
    public static Optional<KeyPair> keyPair(String pemPath) {
        // Load BouncyCastle as JCA provider
        Security.addProvider(new BouncyCastleProvider());

        // Parse the EC key pair
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(Files.newInputStream(Paths.get(pemPath))))) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();

            // Convert to Java (JCA) format
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            KeyPair keyPair = converter.getKeyPair(pemKeyPair);

            return Optional.of(keyPair);

        } catch (FileNotFoundException | NoSuchFileException e) {
            LOG.warn("file not found: {}", pemPath);

        } catch (PEMException e) {
            LOG.warn("PEMException {}", e.getMessage());

        } catch (IOException e) {
            LOG.warn("IOException {}", e.getMessage());
        }
        return Optional.empty();
    }
}
//end::clazz[]
