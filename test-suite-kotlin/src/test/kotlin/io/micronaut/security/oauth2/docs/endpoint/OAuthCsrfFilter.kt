package io.micronaut.security.oauth2.docs.endpoint

//tag::imports[]
import io.micronaut.context.annotation.Requires
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.annotation.Filter
import io.micronaut.http.cookie.Cookie
import io.micronaut.http.filter.OncePerRequestHttpServerFilter
import io.micronaut.http.filter.ServerFilterChain
import org.reactivestreams.Publisher

//end::imports[]
@Requires(property = "oauth.csrf")
//tag::class[]
@Filter(value = ["/oauth/login", "/oauth/login/*"])
class OAuthCsrfFilter : OncePerRequestHttpServerFilter() {

    override fun doFilterOnce(request: HttpRequest<*>, chain: ServerFilterChain): Publisher<MutableHttpResponse<*>> {
        val requestParameter = request.parameters["_csrf"]
        val cookieValue = request.cookies.findCookie("_csrf").map { obj: Cookie -> obj.value }.orElse(null)

        return if (cookieValue == null || cookieValue != requestParameter) {
            Publishers.just(HttpResponse.status<Any>(HttpStatus.FORBIDDEN))
        } else {
            chain.proceed(request)
        }
    }
}
//end::class[]