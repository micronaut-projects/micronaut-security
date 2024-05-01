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
class JsonWebTokenParserTest {

    @Test
    void jwtParsing(JsonWebTokenParser<?> parser) {
        String token = Jwts.builder().subject("sergio").compact();
        Optional<Claims> claimsOptional = parser.parseClaims(token);
        assertTrue(claimsOptional.isPresent());
        Claims claims = claimsOptional.get();
        assertEquals("sergio", claims.get(Claims.SUBJECT));
    }
}
