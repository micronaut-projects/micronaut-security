package io.micronaut.security.fetchmetadata;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The Fetch Metadata filter rejects a cross-site request before the security filter asks for
 * authentication.
 */
@Property(name = "spec.name", value = "FetchMetadataBeforeSecurityFilterTest")
@MicronautTest
class FetchMetadataBeforeSecurityFilterTest {

    @Test
    void crossSiteRequestsToASecuredRouteAreForbiddenBeforeAuthentication(@Client("/") HttpClient httpClient) {
        HttpClientResponseException sameOrigin = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(request("same-origin")));
        assertEquals(HttpStatus.UNAUTHORIZED, sameOrigin.getStatus());

        HttpClientResponseException crossSite = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(request("cross-site")));
        assertEquals(HttpStatus.FORBIDDEN, crossSite.getStatus());
    }

    private static HttpRequest<?> request(String site) {
        return HttpRequest.GET("/fetch-metadata-secured")
            .header(HttpHeaders.SEC_FETCH_SITE, site)
            .header(HttpHeaders.SEC_FETCH_MODE, "no-cors")
            .header(HttpHeaders.SEC_FETCH_DEST, "image");
    }

    @Requires(property = "spec.name", value = "FetchMetadataBeforeSecurityFilterTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/fetch-metadata-secured")
    static class SecuredController {
        @Get(produces = MediaType.TEXT_PLAIN)
        String secured() {
            return "secured";
        }
    }
}
