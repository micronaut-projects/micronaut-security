package io.micronaut.security.jwt.tck;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import io.jsonwebtoken.Jwts;
import io.micronaut.security.token.jwt.validator.JsonWebTokenParser;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class JsonWebTokenParserTest {

    @Test
    void jwtParsing(JsonWebTokenParser<JWT> parser) throws ParseException {
        String token = Jwts.builder().subject("sergio").compact();
        Optional<JWT> optionalJWT = parser.parse(token);
        assertTrue(optionalJWT.isPresent());
        JWT jwt = optionalJWT.get();
        assertTrue(jwt instanceof PlainJWT);
        assertEquals("sergio", jwt.getJWTClaimsSet().getSubject());
    }
}
