package io.micronaut.security.token.jwt.cookie

import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject

class JwtCookieConfigurationSpec extends ApplicationContextSpecification {

    @Subject
    @Shared
    JwtCookieConfiguration jwtCookieConfiguration = applicationContext.getBean(JwtCookieConfiguration)

    @Override
    Map<String, Object> getConfiguration() {
        super.getConfiguration() + ['micronaut.security.authentication': 'cookie']
    }

    @Deprecated
    void "it is possible to override success and failure urls via configuration"() {
        expect:
        jwtCookieConfiguration.logoutTargetUrl == '/'
        jwtCookieConfiguration.loginSuccessTargetUrl == '/'
        jwtCookieConfiguration.loginFailureTargetUrl == '/'
    }
}
