package io.micronaut.security.token.jwt.cookie

import edu.umd.cs.findbugs.annotations.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.cookie.Cookie
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.endpoints.LoginController
import io.micronaut.security.endpoints.LogoutController
import io.micronaut.security.token.jwt.bearer.BearerTokenReader
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.testutils.GebEmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton
import java.security.Principal

class JwtCookieAuthenticationSpec extends GebEmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'JwtCookieAuthenticationSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.http.client.followRedirects': false,
                'micronaut.security.endpoints.login.enabled': true,
                'micronaut.security.endpoints.logout.enabled': true,
                'micronaut.security.token.jwt.bearer.enabled': false,
                'micronaut.security.token.jwt.cookie.enabled': true,
                'micronaut.security.redirect.login-failure': '/login/authFailed',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    def "verify jwt cookie authentication works without Geb"() {
        applicationContext.getBean(HomeController.class)
        applicationContext.getBean(LoginAuthController.class)
        applicationContext.getBean(AuthenticationProviderUserPassword.class)
        applicationContext.getBean(AuthenticationProviderUserPassword.class)
        applicationContext.getBean(LoginController.class)
        applicationContext.getBean(LogoutController.class)
        applicationContext.getBean(JwtCookieLoginHandler.class)
        applicationContext.getBean(JwtCookieClearerLogoutHandler.class)
        applicationContext.getBean(SignatureConfiguration.class)
        applicationContext.getBean(SignatureConfiguration.class, Qualifiers.byName("generator"))

        when:
        applicationContext.getBean(EncryptionConfiguration.class)

        then:
        thrown(NoSuchBeanException)

        when:
        applicationContext.getBean(BearerTokenReader.class)

        then:
        thrown(NoSuchBeanException)

        when:
        HttpRequest request = HttpRequest.GET('/')
        HttpResponse<String> rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('You are not logged in')

        when:
        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'foo', password: 'foo'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse<String> loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 303

        and: 'login fails, cookie is not set'
        !loginRsp.getHeaders().get('Set-Cookie')

        when:
        loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        loginRsp = client.exchange(loginRequest, String)

        then:
        loginRsp.status().code == 303

        when:
        String cookie = loginRsp.getHeaders().get('Set-Cookie')
        println cookie
        then:
        cookie
        cookie.contains('JWT=')
        cookie.contains('Path=/')

        when:
        String sessionId = cookie.substring('JWT='.size(), cookie.indexOf(';'))
        request = HttpRequest.GET('/').cookie(Cookie.of('JWT', sessionId))
        rsp = client.exchange(request, String)

        then:
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('sherlock')
    }

    def "verify jwt cookie authentication works"() {
        given:
        browser.baseUrl = "http://localhost:${embeddedServer.port}"

        when:
        to HomePage

        then:
        at HomePage

        when:
        HomePage homePage = browser.page HomePage

        then:
        homePage.username() == null

        when:
        homePage.login()

        then:
        at LoginPage

        when:
        LoginPage loginPage = browser.page LoginPage
        loginPage.login('foo', 'foo')

        then:
        at LoginPage

        and:
        loginPage.hasErrors()

        when:
        loginPage.login('sherlock', 'password')

        then:
        at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.username() == 'sherlock'

        when:
        homePage.logout()

        then:
        at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.username() == null
    }

    @Requires(property = "spec.name", value = "JwtCookieAuthenticationSpec")
    @Singleton
    static class AuthenticationProviderUserPassword implements AuthenticationProvider  {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({emitter ->
                if ( authenticationRequest.getIdentity().equals("sherlock") &&
                        authenticationRequest.getSecret().equals("password") ) {
                    emitter.onNext(new UserDetails((String) authenticationRequest.getIdentity(), new ArrayList<>()))
                    emitter.onComplete()
                } else {
                    emitter.onNext(new AuthenticationFailed())
                    emitter.onComplete()
                }
            }, BackpressureStrategy.ERROR)
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieAuthenticationSpec")
    @Secured("isAnonymous()")
    @Controller("/")
    static class HomeController {

        @Produces(MediaType.TEXT_HTML)
        @Get
        String index(@Nullable Principal principal) {
            return html(principal != null, principal != null ? principal.getName() : null)
        }

        private String html(boolean loggedIn, String username) {
            StringBuilder sb = new StringBuilder()
            sb.append("<!DOCTYPE html>")
            sb.append("<html>")
            sb.append("<head>")
            sb.append("<title>Home</title>")
            sb.append("</head>")
            sb.append("<body>")
            if( loggedIn ) {
                sb.append("<h1>username: <span> "+username+"</span></h1>")
            } else {
                sb.append("<h1>You are not logged in</h1>")
            }
            if( loggedIn ) {
                sb.append("<form action=\"logout\" method=\"POST\">")
                sb.append("<input type=\"submit\" value=\"Logout\" />")
                sb.append("</form>")
            } else {
                sb.append("<p><a href=\"/login/auth\">Login</a></p>")
            }
            sb.append("</body>")
            sb.append("</html>")
            return sb.toString()
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieAuthenticationSpec")
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

