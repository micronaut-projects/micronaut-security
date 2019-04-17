package io.micronaut.security.oauth2.handlers

import io.micronaut.context.ApplicationContext
import spock.lang.Specification

class CookieSuccessfulIdTokenAccessTokenResponseHandlerSpec extends Specification {

    def "CookieSuccessfulIdTokenAccessTokenResponseHandler bean is loaded by default"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.enabled': true,
        ])

        expect:
        applicationContext.containsBean(CookieSuccessfulIdTokenAccessTokenResponseHandler)

        cleanup:
        applicationContext.close()
    }

}
