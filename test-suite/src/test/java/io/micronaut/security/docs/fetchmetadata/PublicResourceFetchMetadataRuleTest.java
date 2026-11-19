package io.micronaut.security.docs.fetchmetadata;

import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "spec.name", value = "PublicResourceFetchMetadataRuleTest")
@MicronautTest
class PublicResourceFetchMetadataRuleTest {

    @Test
    void crossSiteSubresourceRequestsReachOnlyThePublicResource(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        assertEquals(HttpStatus.OK, client.exchange(crossSiteImage("/favicon.ico"), String.class).getStatus());

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(crossSiteImage("/account"), String.class));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }

    private static HttpRequest<?> crossSiteImage(String path) {
        return HttpRequest.GET(path)
            .header(HttpHeaders.SEC_FETCH_SITE, "cross-site")
            .header(HttpHeaders.SEC_FETCH_MODE, "no-cors")
            .header(HttpHeaders.SEC_FETCH_DEST, "image");
    }
}
