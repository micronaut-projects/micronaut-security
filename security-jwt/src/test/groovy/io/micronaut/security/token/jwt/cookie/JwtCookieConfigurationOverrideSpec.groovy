package io.micronaut.security.token.jwt.cookie

import io.micronaut.testutils.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject

class JwtCookieConfigurationOverrideSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.cookie.enabled': true,
                'micronaut.security.token.jwt.cookie.logout-target-url': '/logout',
                'micronaut.security.token.jwt.cookie.login-success-target-url': '/welcome',
                'micronaut.security.token.jwt.cookie.login-failure-target-url': '/login',
        ]
    }

    @Subject
    @Shared
    JwtCookieConfiguration jwtCookieConfiguration = applicationContext.getBean(JwtCookieConfiguration)

    @Deprecated
    void "it is possible to override success and failure urls via configuration"() {
        expect:
        jwtCookieConfiguration.logoutTargetUrl == '/logout'
        jwtCookieConfiguration.loginSuccessTargetUrl == '/welcome'
        jwtCookieConfiguration.loginFailureTargetUrl == '/login'
    }
}
