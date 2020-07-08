package io.micronaut.security.session

import io.micronaut.context.annotation.Requires
import io.micronaut.docs.security.session.LoginPage
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.rules.SecurityRule
import io.micronaut.testutils.GebEmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

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
        given:
        browser.baseUrl = "http://localhost:${embeddedServer.port}"

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
    static class AuthenticationProviderUserPassword implements AuthenticationProvider  { // <2>
        @Override
        public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            return Flowable.create({ emitter ->
                if ( authenticationRequest.getIdentity().equals("sherlock") &&
                        authenticationRequest.getSecret().equals("password") ) {
                    UserDetails userDetails = new UserDetails((String) authenticationRequest.getIdentity(), new ArrayList<>());
                    emitter.onNext(userDetails);
                    emitter.onComplete();
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()));
                }


            }, BackpressureStrategy.ERROR);
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