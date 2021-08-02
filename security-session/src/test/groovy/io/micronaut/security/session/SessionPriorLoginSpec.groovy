package io.micronaut.security.session

import io.micronaut.context.annotation.Requires
import io.micronaut.docs.security.session.LoginPage
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.GebEmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton

class SessionPriorLoginSpec extends GebEmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'SessionPriorLoginSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication'           : 'session',
                'micronaut.security.redirect.prior-to-login'  : true,
                'micronaut.security.redirect.unauthorized.url': '/login/auth'
        ]
    }

    void "test prior login behavior"() {
        when:
        go '/secured'

        then:
        at LoginPage

        when:
        LoginPage loginPage = browser.page LoginPage
        loginPage.login('sherlock', 'password')

        then:
        at SecuredPage
    }

    @Singleton
    @Requires(property = "spec.name", value = "SessionPriorLoginSpec")
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider  { // <2>

        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = "spec.name", value = "SessionPriorLoginSpec")
    @Controller("/")
    static class HomeController {

        @Produces(MediaType.TEXT_HTML)
        @Get("/secured")
        @Secured(SecurityRule.IS_AUTHENTICATED)
        String securedPage() {
            StringBuilder sb = new StringBuilder()
            sb.append("<!DOCTYPE html>")
            sb.append("<html>")
            sb.append("<head>")
            sb.append("<title>Secured Page</title>")
            sb.append("</head>")
            sb.append("<body>")
            sb.append("</body>")
            sb.append("</html>")
            return sb.toString()
        }
    }

    @Requires(property = "spec.name", value = "SessionPriorLoginSpec")
    @Secured("isAnonymous()")
    @Controller("/login")
    static class LoginAuthController {

        @Produces(MediaType.TEXT_HTML)
        @Get("/auth")
        String auth() {
            return html(false)
        }

        @Produces(MediaType.TEXT_HTML)
        @Get("/authFailed")
        String authFailed() {
            return html(true)
        }

        private String html(boolean errors) {
            StringBuilder sb = new StringBuilder()
            sb.append("<!DOCTYPE html>")
            sb.append("<html>")
            sb.append("<head>")
            if( errors ) {
                sb.append("<title>Login Failed</title>")
            } else {
                sb.append("<title>Login</title>")
            }
            sb.append("</head>")
            sb.append("<body>")
            sb.append("<form action=\"/login\" method=\"POST\">")
            sb.append("<ol>")
            sb.append("<li>")
            sb.append("<label for=\"username\">Username</label>")
            sb.append("<input type=\"text\" name=\"username\" id=\"username\"/>")
            sb.append("</li>")
            sb.append("<li>")
            sb.append("<label for=\"password\">Password</label>")
            sb.append("<input type=\"text\" name=\"password\" id=\"password\"/>")
            sb.append("</li>")
            sb.append("<li>")
            sb.append("<input type=\"submit\" value=\"Login\"/>")
            sb.append("</li>")
            if( errors ) {
                sb.append("<li id=\"errors\">")
                sb.append("<span style=\"color:red\">Login Failed</span>")
                sb.append("</li>")
            }
            sb.append("</ol>")
            sb.append("</form>")
            sb.append("</body>")
            sb.append("</html>")
            return sb.toString()
        }
    }
}