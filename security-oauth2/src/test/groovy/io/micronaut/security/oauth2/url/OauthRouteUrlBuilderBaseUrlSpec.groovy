package io.micronaut.security.oauth2.url

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpRequest
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder
import spock.lang.Specification

/**
 * The absolute callback, login and end-session URLs are, by default, derived from the request
 * {@code Host} / {@code X-Forwarded-*} headers. {@code micronaut.security.oauth2.base-url} pins the base explicitly.
 */
class OauthRouteUrlBuilderBaseUrlSpec extends Specification {

    private static HttpRequest<?> spoofedRequest() {
        HttpRequest.GET("/foo")
                .header("Host", "evil.example.com")
                .header("X-Forwarded-Host", "evil.example.com")
                .header("X-Forwarded-Proto", "https")
    }

    void "without base-url the callback, login and end-session URLs reflect the request Host and X-Forwarded-Host headers"() {
        given:
        ApplicationContext ctx = ApplicationContext.run(['spec.name': 'OauthRouteUrlBuilderBaseUrlSpec'])
        OauthRouteUrlBuilder<HttpRequest<?>> builder = ctx.getBean(OauthRouteUrlBuilder)
        EndSessionCallbackUrlBuilder<HttpRequest<?>> endSessionBuilder = ctx.getBean(EndSessionCallbackUrlBuilder)

        expect: 'this documents the default behaviour: the attacker-supplied host is reflected'
        builder.buildCallbackUrl(spoofedRequest(), "twitter") == new URL("https://evil.example.com/oauth/callback/twitter")
        builder.buildLoginUrl(spoofedRequest(), "twitter") == new URL("https://evil.example.com/oauth/login/twitter")
        endSessionBuilder.build(spoofedRequest()) == new URL("https://evil.example.com/logout")

        cleanup:
        ctx.close()
    }

    void "with base-url #baseUrl the callback, login and end-session URLs use the configured base regardless of the request headers"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'spec.name': 'OauthRouteUrlBuilderBaseUrlSpec',
                'micronaut.security.oauth2.base-url': baseUrl
        ])
        OauthRouteUrlBuilder<HttpRequest<?>> builder = ctx.getBean(OauthRouteUrlBuilder)
        EndSessionCallbackUrlBuilder<HttpRequest<?>> endSessionBuilder = ctx.getBean(EndSessionCallbackUrlBuilder)

        expect:
        builder.buildCallbackUrl(spoofedRequest(), "twitter") == new URL("https://app.example.com/oauth/callback/twitter")
        builder.buildLoginUrl(spoofedRequest(), "twitter") == new URL("https://app.example.com/oauth/login/twitter")
        endSessionBuilder.build(spoofedRequest()) == new URL("https://app.example.com/logout")

        and: 'a null request is fine too'
        builder.buildCallbackUrl(null, "twitter") == new URL("https://app.example.com/oauth/callback/twitter")

        cleanup:
        ctx.close()

        where:
        baseUrl << ['https://app.example.com', 'https://app.example.com/']
    }

    void "an absolute callback-uri still wins over base-url"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'spec.name': 'OauthRouteUrlBuilderBaseUrlSpec',
                'micronaut.security.oauth2.base-url': 'https://app.example.com',
                'micronaut.security.oauth2.callback-uri': 'http://foo.bar/callback/{provider}'
        ])
        OauthRouteUrlBuilder<HttpRequest<?>> builder = ctx.getBean(OauthRouteUrlBuilder)

        expect:
        builder.buildCallbackUrl(spoofedRequest(), "twitter") == new URL("http://foo.bar/callback/twitter")

        cleanup:
        ctx.close()
    }
}
