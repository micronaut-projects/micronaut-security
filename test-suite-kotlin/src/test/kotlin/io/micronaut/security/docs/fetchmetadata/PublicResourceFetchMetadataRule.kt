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

@Requires(property = "spec.name", value = "PublicResourceFetchMetadataRuleTest")
// tag::clazz[]
@Singleton
class PublicResourceFetchMetadataRule : HttpRequestFetchMetadataRule {

    override fun check(request: HttpRequest<*>, secFetch: SecFetch?): FetchMetadataRuleResult =
        if (request.path == "/favicon.ico") {
            FetchMetadataRuleResult.ALLOWED
        } else {
            FetchMetadataRuleResult.UNKNOWN
        }

    override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE
}
// end::clazz[]
