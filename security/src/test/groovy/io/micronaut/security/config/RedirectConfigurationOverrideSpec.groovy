package io.micronaut.security.config

import io.micronaut.security.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject

class RedirectConfigurationOverrideSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.redirect.login-success': '/welcome',
                'micronaut.security.redirect.login-failure': '/login',
                'micronaut.security.redirect.logout': '/goodbye',
                'micronaut.security.redirect.forbidden.url': '/forbidden',
                'micronaut.security.redirect.forbidden.enabled': false,
                'micronaut.security.redirect.unauthorized.url': '/unauthorized',
                'micronaut.security.redirect.unauthorized.enabled': false,
        ]
    }

    @Subject
    @Shared
    RedirectConfiguration redirectConfiguration = applicationContext.getBean(RedirectConfiguration)

    void "it is possible to override success and failure urls via configuration"() {
        expect:
        redirectConfiguration.loginFailure == '/login'
        redirectConfiguration.forbidden.url == '/forbidden'
        redirectConfiguration.unauthorized.url == '/unauthorized'
        !redirectConfiguration.forbidden.enabled
        !redirectConfiguration.unauthorized.enabled
        redirectConfiguration.loginSuccess == '/welcome'
        redirectConfiguration.logout == '/goodbye'
    }
}
