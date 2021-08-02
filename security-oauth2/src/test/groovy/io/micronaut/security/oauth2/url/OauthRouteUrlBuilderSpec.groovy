package io.micronaut.security.oauth2.url

import io.micronaut.http.HttpRequest
import io.micronaut.security.testutils.ApplicationContextSpecification

class OauthRouteUrlBuilderSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.callback-uri': 'http://foo.bar/callback/{provider}'
        ]
    }
    void "test an absolute uri"() {
        given:
        OauthRouteUrlBuilder oauthRouteUrlBuilder = applicationContext.getBean(OauthRouteUrlBuilder)
        HttpRequest<?> request = HttpRequest.GET("/foo")

        expect:
        oauthRouteUrlBuilder.buildCallbackUrl(request, "twitter") == new URL("http://foo.bar/callback/twitter")
    }
}
