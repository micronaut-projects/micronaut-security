package io.micronaut.security.config

import io.micronaut.security.ApplicationContextSpecification
import spock.lang.PendingFeature

class TokenCookieConfigurationSpec extends ApplicationContextSpecification {

    @PendingFeature
    void "TokenCookieConfiguration exists"() {
        expect:
        applicationContext.containsBean(TokenCookieConfiguration)
    }
}
