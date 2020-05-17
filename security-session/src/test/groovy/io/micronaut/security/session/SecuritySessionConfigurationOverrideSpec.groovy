package io.micronaut.security.session

import io.micronaut.security.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject

class SecuritySessionConfigurationOverrideSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security..jwt.cookie.logout-target-url': '/logout',
                'micronaut.security.session.login-success-target-url': '/welcome',
                'micronaut.security.session.login-failure-target-url': '/login',
                'micronaut.security.session.logout-target-url': '/logout',
                'micronaut.security.session.unauthorized-target-url': '/unauthorized',
                'micronaut.security.session.forbidden-target-url': '/forbidden',
                'micronaut.security.session.redirect-on-rejection': false,
        ]
    }

    @Subject
    @Shared
    SecuritySessionConfiguration sessionConfiguration = applicationContext.getBean(SecuritySessionConfiguration)

    void "it is possible to override success and failure urls via configuration"() {
        expect:
        sessionConfiguration.loginSuccessTargetUrl == '/welcome'
        sessionConfiguration.logoutTargetUrl == '/logout'
        sessionConfiguration.loginFailureTargetUrl == '/login'
        sessionConfiguration.unauthorizedTargetUrl == '/unauthorized'
        sessionConfiguration.forbiddenTargetUrl == '/forbidden'
        !sessionConfiguration.redirectOnRejection
    }

}
