# tag::imports[]
from micronaut.context.annotation import Requires
from micronaut.core.async_.publisher import Publishers
from micronaut.http import HttpRequest, HttpResponse, HttpStatus, MutableHttpResponse
from micronaut.http.annotation import Filter
from micronaut.http.filter import HttpServerFilter, ServerFilterChain
from org.reactivestreams import Publisher
# end::imports[]


@Requires(property="oauth.csrf")
# tag::class[]
@Filter(value=["/oauth/login", "/oauth/login/*"])
class OAuthCsrfFilter(HttpServerFilter):

    def doFilter(self, request: HttpRequest, chain: ServerFilterChain) -> Publisher[MutableHttpResponse]:
        requestParameter = request.getParameters().get("_csrf")
        cookieValue = request.getCookies().findCookie("_csrf").map(lambda cookie: cookie.getValue()).orElse(None)

        if cookieValue is None or cookieValue != requestParameter:
            return Publishers.just(HttpResponse.status(HttpStatus.FORBIDDEN))

        return chain.proceed(request)
# end::class[]
