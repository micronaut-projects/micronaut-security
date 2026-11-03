package io.micronaut.security.errors

import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MutableHttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.cookie.Cookie
import io.micronaut.http.simple.SimpleHttpRequest
import spock.lang.Specification
import spock.lang.Unroll

class CookiePriorToLoginPersistenceSpec extends Specification {

    private static final String COOKIE_NAME = 'ORIGINAL_URI'

    CookiePriorToLoginPersistence persistence = new CookiePriorToLoginPersistence(null)

    private static MutableHttpRequest<?> request(String uri) {
        // server-side request implementation: the Netty client request does not implement getCookies()
        new SimpleHttpRequest<>(HttpMethod.GET, uri, null)
    }

    void "onUnauthorized stores only the path and query of the request, never the scheme or host"() {
        given:
        HttpRequest<?> request = request('http://localhost:8080/secured/page?foo=bar&baz=qux')
        MutableHttpResponse<?> response = HttpResponse.ok()

        when:
        persistence.onUnauthorized(request, response)
        Cookie cookie = response.getCookie(COOKIE_NAME).orElse(null)

        then:
        cookie
        cookie.value == '/secured/page?foo=bar&baz=qux'
        cookie.httpOnly
        cookie.path == '/'
        cookie.maxAge == 300
    }

    void "onUnauthorized stores the root path when the request has no path"() {
        given:
        HttpRequest<?> request = request('http://localhost:8080')
        MutableHttpResponse<?> response = HttpResponse.ok()

        when:
        persistence.onUnauthorized(request, response)

        then:
        response.getCookie(COOKIE_NAME).map(Cookie::getValue).orElse(null) == '/'
    }

    void "a relative path with a query string round-trips and the cookie is cleared"() {
        given:
        MutableHttpRequest<?> request = request('/login').cookie(Cookie.of(COOKIE_NAME, '/secured/page?foo=bar&baz=qux'))
        MutableHttpResponse<?> response = HttpResponse.ok()

        when:
        Optional<URI> uri = persistence.getOriginalUri(request, response)

        then:
        uri.isPresent()
        uri.get().toString() == '/secured/page?foo=bar&baz=qux'
        uri.get().scheme == null
        uri.get().rawAuthority == null

        and: 'the cookie is expired'
        response.getCookie(COOKIE_NAME).isPresent()
        response.getCookie(COOKIE_NAME).get().value == ''
        response.getCookie(COOKIE_NAME).get().maxAge == 0
    }

    void "getOriginalUri is empty when there is no cookie"() {
        given:
        HttpRequest<?> request = request('/login')
        MutableHttpResponse<?> response = HttpResponse.ok()

        expect:
        !persistence.getOriginalUri(request, response).isPresent()
        !response.getCookie(COOKIE_NAME).isPresent()
    }

    @Unroll
    void "getOriginalUri rejects #description and clears the cookie"(String value, String description) {
        given:
        MutableHttpRequest<?> request = request('/login').cookie(Cookie.of(COOKIE_NAME, value))
        MutableHttpResponse<?> response = HttpResponse.ok()

        when:
        Optional<URI> uri = persistence.getOriginalUri(request, response)

        then:
        !uri.isPresent()

        and: 'the cookie is expired'
        response.getCookie(COOKIE_NAME).isPresent()
        response.getCookie(COOKIE_NAME).get().maxAge == 0

        where:
        value                              | description
        'https://evil.example/x'           | 'an absolute https URI'
        'http://evil.example/x'            | 'an absolute http URI'
        'HTTPS://evil.example/x'           | 'an absolute URI with an upper-case scheme'
        'javascript:alert(1)'              | 'a javascript URI'
        'mailto:someone@evil.example'      | 'a mailto URI'
        '//evil.example/x'                 | 'a protocol-relative URI'
        '\\\\evil.example/x'               | 'a backslash protocol-relative URI'
        '\\evil.example/x'                 | 'a URI starting with a backslash'
        '/\\evil.example/x'                | 'a path containing a backslash'
        'http:/evil.example/x'             | 'a scheme with a single slash'
        ':::'                              | 'a malformed URI'
        '/secured page'                    | 'a URI with an unencoded space'
        ''                                 | 'an empty value'
    }

    @Unroll
    void "getOriginalUri accepts #value"(String value) {
        given:
        MutableHttpRequest<?> request = request('/login').cookie(Cookie.of(COOKIE_NAME, value))
        MutableHttpResponse<?> response = HttpResponse.ok()

        when:
        Optional<URI> uri = persistence.getOriginalUri(request, response)

        then:
        uri.isPresent()
        uri.get().toString() == value

        where:
        value << ['/', '/secured', '/secured/', '/secured?foo=bar', '/a/b/c?x=1&y=2', '/secured?redirect=https://evil.example']
    }
}
