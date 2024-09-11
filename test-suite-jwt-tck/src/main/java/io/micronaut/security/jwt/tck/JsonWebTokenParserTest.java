package io.micronaut.security.jwt.tck;

import io.jsonwebtoken.Jwts;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.jwt.validator.JsonWebTokenParser;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
@SuppressWarnings({
    "java:S5960", // this is a TCK test class, so assertions are expected
    "java:S5659", // This is a TCK test class, we don't need a strong cypher algorithm for the signed token
})
class JsonWebTokenParserTest {

    @Test
    void jwtParsing(JsonWebTokenParser<?> parser) {
        String token = Jwts.builder().subject("sergio").compact();
        Optional<Claims> claimsOptional = parser.parseClaims(token);
        assertTrue(claimsOptional.isPresent());
        Object subject = claimsOptional.map(c -> c.get(Claims.SUBJECT)).orElse(null);
        assertEquals("sergio", subject);
    }
}
