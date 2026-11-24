package io.micronaut.security.oauth2.docs.endpoint

//tag::imports[]
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.annotation.Filter
import io.micronaut.http.filter.HttpServerFilter
import io.micronaut.http.filter.ServerFilterChain
import org.reactivestreams.Publisher

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

//end::imports[]
@Requires(property = "oauth.csrf")
//tag::class[]
@Filter(value = ["/oauth/login", "/oauth/login/*"])
class OAuthCsrfFilter implements HttpServerFilter {

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        String requestParameter = request.parameters.get("_csrf")
        String cookieValue = request.cookies.findCookie("_csrf").map({c -> c.getValue()}).orElse(null)

        if (cookieValue == null || requestParameter == null || !matches(cookieValue, requestParameter)) {
            return Publishers.just(HttpResponse.status(HttpStatus.FORBIDDEN))
        }

        return chain.proceed(request)
    }

    private static boolean matches(String expected, String actual) {
        // constant-time comparison, so that response timing does not reveal the token
        MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8))
    }
}
//end::class[]