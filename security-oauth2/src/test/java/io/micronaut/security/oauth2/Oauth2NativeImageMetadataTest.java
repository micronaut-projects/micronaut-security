package io.micronaut.security.oauth2;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Oauth2NativeImageMetadataTest {

    private static final String NATIVE_IMAGE_PROPERTIES = "META-INF/native-image/io.micronaut.security/micronaut-security-oauth2/native-image.properties";

    @Test
    void nativeImageMetadataInitializesSessionPersistenceBeanDefinitionsAtRunTime() throws IOException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(NATIVE_IMAGE_PROPERTIES);
        assertNotNull(inputStream);

        String properties;
        try (inputStream) {
            properties = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }

        assertTrue(properties.contains("--initialize-at-run-time="));
        assertTrue(properties.contains("io.micronaut.security.oauth2.endpoint.nonce.persistence.session.$SessionNoncePersistence$Definition"));
        assertTrue(properties.contains("io.micronaut.security.oauth2.endpoint.authorization.state.persistence.session.$SessionStatePersistence$Definition"));
        assertTrue(properties.contains("io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.session.$SessionPkcePersistence$Definition"));
    }
}
