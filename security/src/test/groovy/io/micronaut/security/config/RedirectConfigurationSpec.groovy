package io.micronaut.security.config

import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject

class RedirectConfigurationSpec extends ApplicationContextSpecification {

    @Subject
    @Shared
    RedirectConfiguration redirectConfiguration = applicationContext.getBean(RedirectConfiguration)

    void "login-success defaults to /"() {
        expect:
        redirectConfiguration.loginSuccess == '/'
    }

    void "login-failure defaults to /"() {
        expect:
        redirectConfiguration.loginFailure == '/'
    }

    void "logout defaults to /"() {
        expect:
        redirectConfiguration.logout == '/'
    }

    void "forbidden defaults to /"() {
        expect:
        redirectConfiguration.forbidden.url == '/'
    }

    void "unauthorized defaults to /"() {
        expect:
        redirectConfiguration.unauthorized.url == '/'
    }

    void "unauthorized redirection is enabled by default"() {
        expect:
        redirectConfiguration.unauthorized.enabled
    }

    void "forbidden redirection is enabled by default"() {
        expect:
        redirectConfiguration.forbidden.enabled
    }
}
