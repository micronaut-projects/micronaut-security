package io.micronaut.security.docs.fetchmetadata

import io.micronaut.http.HttpRequest
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class PublicResourceFetchMetadataRuleTest {

    private val rule = PublicResourceFetchMetadataRule()

    @Test
    fun allowsOnlyThePublicResource() {
        assertEquals(
            FetchMetadataRuleResult.ALLOWED,
            rule.check(HttpRequest.GET<Any>("/favicon.ico"), null)
        )
        assertEquals(
            FetchMetadataRuleResult.UNKNOWN,
            rule.check(HttpRequest.GET<Any>("/account"), null)
        )
    }
}
