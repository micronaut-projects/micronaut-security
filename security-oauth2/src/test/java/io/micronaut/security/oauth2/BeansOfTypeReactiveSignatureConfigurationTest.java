package io.micronaut.security.oauth2;

import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Property;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "micronaut.security.token.jwt.signatures.jwks.google.url", value = "https://www.googleapis.com/oauth2/v3/certs")
@MicronautTest(startApplication = false)
class BeansOfTypeReactiveSignatureConfigurationTest {
    @Inject
    List<ReactiveSignatureConfiguration<SignedJWT>> signatures;

    @Disabled("https://github.com/micronaut-projects/micronaut-security/issues/1775")
    @Test
    void testThereIsOnlyOneBeanOfTypeReactiveSignatureConfiguration() {
        assertEquals(1, signatures.size());
    }
}
