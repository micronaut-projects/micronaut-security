package io.micronaut.security.serdetests;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Property(name = "spec.name", value = "AccessRefreshTokenSerdeSpec")
@Property(name = "micronaut.security.reject-not-found", value = StringUtils.FALSE)
@MicronautTest
public class AccessRefreshTokenSerdeSpec {
    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void accessRefreshTokenIsSerdeable() {
        BlockingHttpClient client = httpClient.toBlocking();
        String json = client.retrieve(HttpRequest.GET("/accessRefreshToken"));
        assertNotNull(json);
        assertEquals("{\"access_token\":\"xxx.yyy.zzz\",\"refresh_token\":\"zzzzooouuu\",\"token_type\":\"Bearer\",\"expires_in\":3600}", json);
    }

    @Requires(property = "spec.name", value = "AccessRefreshTokenSerdeSpec")
    @Controller("/accessRefreshToken")
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class AccessRefreshTokenSerdeController {

        @Get
        AccessRefreshToken index() {
            return new AccessRefreshToken("xxx.yyy.zzz", "zzzzooouuu", "Bearer", 3600);
        }
    }
}
