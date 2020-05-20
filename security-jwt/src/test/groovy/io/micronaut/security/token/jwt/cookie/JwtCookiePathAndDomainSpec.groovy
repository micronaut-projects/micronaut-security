package io.micronaut.security.token.jwt.cookie

import edu.umd.cs.findbugs.annotations.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.cookie.Cookie
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.testutils.EmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton
import java.security.Principal

class JwtCookiePathAndDomainSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'JwtCookiePathAndDomainSpec'
    }

    Map<String, Object> getConfiguration() {
        super.configuration + [
                    'micronaut.http.client.followRedirects': false,
                    'micronaut.security.endpoints.login.enabled': true,
                    'micronaut.security.token.jwt.bearer.enabled': false,
                    'micronaut.security.token.jwt.cookie.enabled': true,
                    'micronaut.security.token.jwt.cookie.cookie-path': "/path",
                    'micronaut.security.token.jwt.cookie.cookie-domain': "example.com",
                    'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
            ]
    }

    def "verify jwt cookie path and domain is set from configuration"() {

        when:
        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse<String> loginRsp = client.exchange(loginRequest, String)

        then:
        noExceptionThrown()
        loginRsp.status().code == 303

        when:
        String cookie = loginRsp.getHeaders().get('Set-Cookie')
        println cookie
        then:
        cookie
        cookie.contains('JWT=')
        cookie.contains('Domain=example.com')
        cookie.contains('Path=/path;')

        when:
        String sessionId = cookie.substring('JWT='.size(), cookie.indexOf(';'))
        HttpRequest request = HttpRequest.GET('/').cookie(Cookie.of('JWT', sessionId))
        HttpResponse<String> rsp = client.exchange(request, String)

        then:
        noExceptionThrown()
        rsp.status().code == 200
        rsp.body()
        rsp.body().contains('sherlock')

        when:
        HttpRequest logoutRequest = HttpRequest.POST('/logout', "").cookie(Cookie.of('JWT', sessionId))
        HttpResponse<String> logoutRsp = client.exchange(logoutRequest, String)

        then:
        noExceptionThrown()
        logoutRsp.status().code == 303

        when:
        String logoutCookie = logoutRsp.getHeaders().get('Set-Cookie')

        then:
        logoutCookie
        logoutCookie.contains('JWT=')
        logoutCookie.contains('Domain=example.com')
        logoutCookie.contains('Path=/path;')
        logoutCookie.contains('Max-Age=0;')
    }

    @Requires(property = "spec.name", value = "JwtCookiePathAndDomainSpec")
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

    @Requires(property = "spec.name", value = "JwtCookiePathAndDomainSpec")
    @Singleton
    static class AuthenticationProviderUserPassword implements AuthenticationProvider  {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {

            Flowable.create({ emitter ->
                if ( authenticationRequest.getIdentity() == "sherlock" && authenticationRequest.getSecret() == "password") {
                    emitter.onNext(new UserDetails((String) authenticationRequest.getIdentity(), new ArrayList<>()))
                    emitter.onComplete()
                } else {
                    emitter.onNext(new AuthenticationFailed())
                    emitter.onComplete()
                }
            }, BackpressureStrategy.ERROR)
        }
    }

}
