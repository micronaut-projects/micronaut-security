package io.micronaut.security.docs.fetchmetadata

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "PublicResourceFetchMetadataRuleTest")
@MicronautTest
internal class PublicResourceFetchMetadataRuleTest {

    @Test
    fun crossSiteSubresourceRequestsReachOnlyThePublicResource(@Client("/") httpClient: HttpClient) {
        val client = httpClient.toBlocking()

        assertEquals(HttpStatus.OK, client.exchange(crossSiteImage("/favicon.ico"), String::class.java).status)

        val exception = assertThrows(HttpClientResponseException::class.java) {
            client.exchange(crossSiteImage("/account"), String::class.java)
        }
        assertEquals(HttpStatus.FORBIDDEN, exception.status)
    }

    private fun crossSiteImage(path: String): HttpRequest<*> =
        HttpRequest.GET<Any>(path)
            .header(HttpHeaders.SEC_FETCH_SITE, "cross-site")
            .header(HttpHeaders.SEC_FETCH_MODE, "no-cors")
            .header(HttpHeaders.SEC_FETCH_DEST, "image")

    @Requires(property = "spec.name", value = "PublicResourceFetchMetadataRuleTest")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    internal class PublicResourceController {
        @Get(uri = "/favicon.ico", produces = [MediaType.TEXT_PLAIN])
        fun favicon(): String = "icon"

        @Get(uri = "/account", produces = [MediaType.TEXT_PLAIN])
        fun account(): String = "account"
    }
}
