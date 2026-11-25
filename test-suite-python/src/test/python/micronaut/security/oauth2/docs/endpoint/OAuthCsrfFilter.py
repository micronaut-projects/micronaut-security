# tag::imports[]
import hmac

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

        # hmac.compare_digest compares in constant time, so that response timing does not reveal the token
        if cookieValue is None or requestParameter is None or not hmac.compare_digest(
                cookieValue.encode("utf-8"), requestParameter.encode("utf-8")):
            return Publishers.just(HttpResponse.status(HttpStatus.FORBIDDEN))

        return chain.proceed(request)
# end::class[]
