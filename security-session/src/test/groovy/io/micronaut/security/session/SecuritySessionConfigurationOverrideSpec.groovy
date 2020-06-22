package io.micronaut.security.session

import io.micronaut.context.ApplicationContext
import io.micronaut.security.config.RedirectConfiguration
import spock.lang.Specification

class SecuritySessionConfigurationOverrideSpec extends Specification {

    @Deprecated
    void "old security session configuration still works"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.session.login-success-target-url': '/welcome',
                'micronaut.security.session.login-failure-target-url': '/login',
                'micronaut.security.session.logout-target-url': '/logout',
                'micronaut.security.session.unauthorized-target-url': '/unauthorized',
                'micronaut.security.session.forbidden-target-url': '/forbidden',
                'micronaut.security.session.redirect-on-rejection': false,
        ])
        SecuritySessionConfiguration sessionConfiguration = applicationContext.getBean(SecuritySessionConfiguration)
        RedirectConfiguration redirectConfiguration = applicationContext.getBean(RedirectConfiguration)

        expect:
        redirectConfiguration.loginSuccess == '/welcome'
        sessionConfiguration.loginSuccessTargetUrl == '/welcome'
        redirectConfiguration.logout == '/logout'
        sessionConfiguration.logoutTargetUrl == '/logout'
        redirectConfiguration.loginFailure == '/login'
        sessionConfiguration.loginFailureTargetUrl == '/login'
        redirectConfiguration.unauthorized.url == '/unauthorized'
        sessionConfiguration.unauthorizedTargetUrl == '/unauthorized'
        sessionConfiguration.forbiddenTargetUrl == '/forbidden'
        redirectConfiguration.forbidden.url == '/forbidden'
        !sessionConfiguration.redirectOnRejection
        !redirectConfiguration.forbidden.enabled
        !redirectConfiguration.unauthorized.enabled

        cleanup:
        applicationContext.close()
    }

    @Deprecated
    void "new settings take precedence over old session configuration"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.redirect.login-success': '/newwelcome',
                'micronaut.security.redirect.login-failure': '/newlogin',
                'micronaut.security.redirect.logout': '/newlogout',
                'micronaut.security.redirect.unauthorized.url': '/newunauthorized',
                'micronaut.security.redirect.forbidden.url': '/newforbidden',
                'micronaut.security.redirect.unauthorized.enabled': true,
                'micronaut.security.redirect.forbidden.enabled': true,

                'micronaut.security.session.login-success-target-url': '/welcome',
                'micronaut.security.session.login-failure-target-url': '/login',
                'micronaut.security.session.logout-target-url': '/logout',
                'micronaut.security.session.unauthorized-target-url': '/unauthorized',
                'micronaut.security.session.forbidden-target-url': '/forbidden',
                'micronaut.security.session.redirect-on-rejection': false,
        ])
        SecuritySessionConfiguration sessionConfiguration = applicationContext.getBean(SecuritySessionConfiguration)
        RedirectConfiguration redirectConfiguration = applicationContext.getBean(RedirectConfiguration)

        expect:
        redirectConfiguration.loginSuccess == '/newwelcome'
        sessionConfiguration.loginSuccessTargetUrl == '/newwelcome'
        redirectConfiguration.logout == '/newlogout'
        sessionConfiguration.logoutTargetUrl == '/newlogout'
        redirectConfiguration.loginFailure == '/newlogin'
        sessionConfiguration.loginFailureTargetUrl == '/newlogin'
        redirectConfiguration.unauthorized.url == '/newunauthorized'
        sessionConfiguration.unauthorizedTargetUrl == '/newunauthorized'
        sessionConfiguration.forbiddenTargetUrl == '/newforbidden'
        redirectConfiguration.forbidden.url == '/newforbidden'
        sessionConfiguration.redirectOnRejection
        redirectConfiguration.forbidden.enabled
        redirectConfiguration.unauthorized.enabled

        cleanup:
        applicationContext.close()
    }

}
