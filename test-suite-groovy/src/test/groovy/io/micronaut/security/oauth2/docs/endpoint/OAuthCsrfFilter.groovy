package io.micronaut.security.oauth2.docs.endpoint

//tag::imports[]
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.annotation.Filter
import io.micronaut.http.filter.OncePerRequestHttpServerFilter
import io.micronaut.http.filter.ServerFilterChain
import org.reactivestreams.Publisher

//end::imports[]
@Requires(property = "oauth.csrf")
//tag::class[]
@Filter(value = ["/oauth/login", "/oauth/login/*"])
class OAuthCsrfFilter extends OncePerRequestHttpServerFilter {

    @Override
    protected Publisher<MutableHttpResponse<?>> doFilterOnce(HttpRequest<?> request, ServerFilterChain chain) {
        String requestParameter = request.parameters.get("_csrf")
        String cookieValue = request.cookies.findCookie("_csrf").map({c -> c.getValue()}).orElse(null)

        if (cookieValue == null || cookieValue != requestParameter) {
            return Publishers.just(HttpResponse.status(HttpStatus.FORBIDDEN))
        }

        return chain.proceed(request)
    }
}
//end::class[]