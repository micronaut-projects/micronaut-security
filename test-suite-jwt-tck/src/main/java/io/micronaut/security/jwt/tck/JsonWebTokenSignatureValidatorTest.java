package io.micronaut.security.jwt.tck;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.util.StringUtils;
import reactor.core.publisher.Mono;
import io.micronaut.security.token.jwt.validator.JsonWebTokenValidator;
import io.micronaut.security.token.jwt.validator.ReactiveJsonWebTokenValidator;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({
    "java:S5960", // this is a TCK test class, so assertions are expected
    "java:S5659", // This is a TCK test class, we don't need a strong cypher algorithm for the signed token
})
class JsonWebTokenSignatureValidatorTest {

    @Test
    void testValidateSignedToken() {
        SecretKey key = Jwts.SIG.HS256.key().build();
        String secretString = Encoders.BASE64.encode(key.getEncoded());
        Map<String, Object> config = Map.of("micronaut.security.token.jwt.signatures.secret.validator.secret", secretString,
                "micronaut.security.token.jwt.signatures.secret.validator.base64", StringUtils.TRUE);
        try (ApplicationContext context = ApplicationContext.run(config)) {
            String signedToken = Jwts.builder()
                    .subject("Bob")
                    .signWith(key)
                    .compact();
            JsonWebTokenValidator validator = context.getBean(JsonWebTokenValidator.class);
            assertTrue(validator.validate(signedToken, null).isPresent());
            ReactiveJsonWebTokenValidator reactiveValidator = context.getBean(ReactiveJsonWebTokenValidator.class);
            Optional result = Mono.from(reactiveValidator.validate(signedToken, null)).blockOptional();
            assertTrue(result.isPresent());
        }
    }

    @Test
    void testValidateNotSignedToken() {
        SecretKey key = Jwts.SIG.HS256.key().build();
        String secretString = Encoders.BASE64.encode(key.getEncoded());
        Map<String, Object> config = Map.of("micronaut.security.token.jwt.signatures.secret.validator.secret", secretString,
                "micronaut.security.token.jwt.signatures.secret.validator.base64", StringUtils.TRUE);
        try (ApplicationContext context = ApplicationContext.run(config)) {
            JsonWebTokenValidator validator = context.getBean(JsonWebTokenValidator.class);
            String notSignedToken = Jwts.builder()
                    .subject("Bob")
                    .compact();
            assertFalse(validator.validate(notSignedToken, null).isPresent());

            ReactiveJsonWebTokenValidator reactiveValidator = context.getBean(ReactiveJsonWebTokenValidator.class);
            Optional result = Mono.from(reactiveValidator.validate(notSignedToken, null)).blockOptional();
            assertTrue(result.isEmpty());
        }
    }
}
