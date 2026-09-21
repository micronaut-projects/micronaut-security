package io.micronaut.security.docs.fetchmetadata;

import io.micronaut.context.annotation.Requires;

// tag::imports[]
import io.micronaut.core.order.Ordered;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.SecFetch;
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult;
import io.micronaut.security.fetchmetadata.HttpRequestFetchMetadataRule;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
// end::imports[]

@Requires(property = "spec.name", value = "PublicResourceFetchMetadataRuleTest")
// tag::clazz[]
@Singleton
public final class PublicResourceFetchMetadataRule implements HttpRequestFetchMetadataRule {

    @Override
    public FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch) {
        return request.getPath().equals("/favicon.ico")
            ? FetchMetadataRuleResult.ALLOWED
            : FetchMetadataRuleResult.UNKNOWN;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
// end::clazz[]
