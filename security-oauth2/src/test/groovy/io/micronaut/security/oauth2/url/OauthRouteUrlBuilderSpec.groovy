package io.micronaut.security.oauth2.url

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpRequest
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.Specification

class OauthRouteUrlBuilderSpec extends Specification {

    void "test an absolute uri"() {
        given:
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'micronaut.security.oauth2.callback-uri': 'http://foo.bar/callback/{provider}'
        ])
        OauthRouteUrlBuilder urlBuilder = server.applicationContext.getBean(OauthRouteUrlBuilder)

        expect:
        urlBuilder.buildCallbackUrl(HttpRequest.GET("/foo"), "twitter") == new URL("http://foo.bar/callback/twitter")

        cleanup:
        server.close()
    }
}
