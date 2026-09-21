package io.micronaut.security.docs.fetchmetadata

import io.micronaut.http.HttpRequest
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult
import spock.lang.Specification

class PublicResourceFetchMetadataRuleSpec extends Specification {

    private final PublicResourceFetchMetadataRule rule = new PublicResourceFetchMetadataRule()

    void 'allows only the public resource'() {
        expect:
        rule.check(HttpRequest.GET(path), null) == result

        where:
        path           | result
        '/favicon.ico' | FetchMetadataRuleResult.ALLOWED
        '/account'     | FetchMetadataRuleResult.UNKNOWN
    }
}
