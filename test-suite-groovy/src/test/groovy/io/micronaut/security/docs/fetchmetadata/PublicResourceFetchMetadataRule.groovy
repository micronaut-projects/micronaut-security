package io.micronaut.security.docs.fetchmetadata

import io.micronaut.context.annotation.Requires

// tag::imports[]
import io.micronaut.core.order.Ordered
import io.micronaut.http.HttpRequest
import io.micronaut.http.SecFetch
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult
import io.micronaut.security.fetchmetadata.HttpRequestFetchMetadataRule
import jakarta.inject.Singleton
// end::imports[]

@Requires(property = 'spec.name', value = 'PublicResourceFetchMetadataRuleSpec')
// tag::clazz[]
@Singleton
class PublicResourceFetchMetadataRule implements HttpRequestFetchMetadataRule {

    @Override
    FetchMetadataRuleResult check(HttpRequest<?> request, SecFetch secFetch) {
        request.path == '/favicon.ico'
            ? FetchMetadataRuleResult.ALLOWED
            : FetchMetadataRuleResult.UNKNOWN
    }

    @Override
    int getOrder() {
        Ordered.HIGHEST_PRECEDENCE
    }
}
// end::clazz[]
