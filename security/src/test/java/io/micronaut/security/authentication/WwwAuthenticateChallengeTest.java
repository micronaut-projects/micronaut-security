package io.micronaut.security.authentication;

import io.micronaut.http.HttpHeaderValues;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class WwwAuthenticateChallengeTest {

    @Test
    void wwwAuthenticateChallengetoString() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("realm", "myapp");
        m.put("charset", "UTF-8");
        String value = new WwwAuthenticateChallenge(HttpHeaderValues.AUTHORIZATION_PREFIX_BASIC, m).toString();
        assertEquals("Basic realm=\"myapp\", charset=\"UTF-8\"", value);
        assertEquals(
            "Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\"",
            WwwAuthenticateChallenge.builder()
                .authScheme("Newauth")
                .param("realm", "apps")
                .param("type", 1)
                .param("title", "Login to \"apps\"")
                .build()
                .toString()
        );
    }
}
