package io.micronaut.security.config

import io.micronaut.security.ApplicationContextSpecification
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
        redirectConfiguration.forbidden == '/'
    }

    void "unauthorized defaults to /"() {
        expect:
        redirectConfiguration.unauthorized == '/'
    }

    void "onRejection defaults to true"() {
        expect:
        redirectConfiguration.onRejection
    }
}
