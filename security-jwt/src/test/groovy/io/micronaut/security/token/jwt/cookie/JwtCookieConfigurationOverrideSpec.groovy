package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.ApplicationContext
import io.micronaut.security.config.RedirectConfiguration
import spock.lang.Specification

class JwtCookieConfigurationOverrideSpec extends Specification {

    @Deprecated
    void "old settings of cookie redirection still work"() {

        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.token.jwt.cookie.logout-target-url': '/logout',
                'micronaut.security.token.jwt.cookie.login-success-target-url': '/welcome',
                'micronaut.security.token.jwt.cookie.login-failure-target-url': '/login',
        ])
        JwtCookieConfiguration jwtCookieConfiguration = applicationContext.getBean(JwtCookieConfiguration)
        RedirectConfiguration redirectConfiguration = applicationContext.getBean(RedirectConfiguration)

        expect:
        redirectConfiguration.logout == '/logout'
        jwtCookieConfiguration.logoutTargetUrl == '/logout'
        redirectConfiguration.loginSuccess == '/welcome'
        jwtCookieConfiguration.loginSuccessTargetUrl == '/welcome'
        redirectConfiguration.loginFailure == '/login'
        jwtCookieConfiguration.loginFailureTargetUrl == '/login'
    }

    @Deprecated
    void "new settings for redirection take precedence over old cookie redirection"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.redirect.logout': '/newlogout',
                'micronaut.security.redirect.login-success': '/newwelcome',
                'micronaut.security.redirect.login-failure': '/newlogin',

                'micronaut.security.token.jwt.cookie.logout-target-url': '/logout',
                'micronaut.security.token.jwt.cookie.login-success-target-url': '/welcome',
                'micronaut.security.token.jwt.cookie.login-failure-target-url': '/login',
        ])
        JwtCookieConfiguration jwtCookieConfiguration = applicationContext.getBean(JwtCookieConfiguration)
        RedirectConfiguration redirectConfiguration = applicationContext.getBean(RedirectConfiguration)

        expect:
        redirectConfiguration.logout == '/newlogout'
        jwtCookieConfiguration.logoutTargetUrl == '/newlogout'
        redirectConfiguration.loginSuccess == '/newwelcome'
        jwtCookieConfiguration.loginSuccessTargetUrl == '/newwelcome'
        redirectConfiguration.loginFailure == '/newlogin'
        jwtCookieConfiguration.loginFailureTargetUrl == '/newlogin'
    }
}
