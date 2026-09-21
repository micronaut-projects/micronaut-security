package io.micronaut.security.docs.fetchmetadata;

import io.micronaut.http.HttpRequest;
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PublicResourceFetchMetadataRuleTest {

    private final PublicResourceFetchMetadataRule rule = new PublicResourceFetchMetadataRule();

    @Test
    void allowsOnlyThePublicResource() {
        assertEquals(FetchMetadataRuleResult.ALLOWED,
            rule.check(HttpRequest.GET("/favicon.ico"), null));
        assertEquals(FetchMetadataRuleResult.UNKNOWN,
            rule.check(HttpRequest.GET("/account"), null));
    }
}
