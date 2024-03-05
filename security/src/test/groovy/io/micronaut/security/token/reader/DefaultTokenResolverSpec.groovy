package io.micronaut.security.token.reader

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.order.Ordered
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpMethod
import io.micronaut.http.simple.SimpleHttpRequest
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import spock.lang.Specification

@Property(name = "spec.name", value = "DefaultTokenResolverSpec")
@MicronautTest
class DefaultTokenResolverSpec extends Specification {

    @Inject
    DefaultTokenResolver defaultTokenResolver

    void "Beans of type TokenReader are evaluated in order"() {
        given:
        SimpleHttpRequest request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "validxxx")

        expect:
        ["validxxx"] == defaultTokenResolver.resolveTokens(request)

        when:
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)

        then:
        !defaultTokenResolver.resolveTokens(request)

        when:
        request = new SimpleHttpRequest(HttpMethod.POST, "/analytics/report", null)
        request.headers.add("X-API-KEY", "validxxx")
        request.headers.add(HttpHeaders.AUTHORIZATION, "Bearer validyyy")

        then:
        ["validxxx", "validyyy"] == defaultTokenResolver.resolveTokens(request)

    }

    @Requires(property = "spec.name", value = "DefaultTokenResolverSpec")
    @Singleton
    static class ApiTokenReader extends HttpHeaderTokenReader {
        @Override
        protected String getPrefix() {
            return null
        }

        @Override
        protected String getHeaderName() {
            return "X-API-KEY"
        }

        @Override
        int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }
    }
}