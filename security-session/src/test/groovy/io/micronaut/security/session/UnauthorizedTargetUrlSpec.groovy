package io.micronaut.security.session

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured

class UnauthorizedTargetUrlSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'UnauthorizedTargetUrlSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.redirect.unauthorized': '/login/auth',
                'micronaut.security.intercept-url-map': [
                        [pattern: '/login/auth', httpMethod: 'GET', access: ['isAnonymous()']]
                ]
        ]
    }

    void "access a secured controller without authentication redirects to micronaut.security.redirect.unauthorized"() {
        when:
        HttpRequest request = HttpRequest.GET("/foo/bar")
                .header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                .header('Accept-Language', 'en-us')
                .header('Accept-Encoding', 'gzip, deflate')
                .header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15')
        client.exchange(request)

        then:
        noExceptionThrown()
    }

    @Requires(property = 'spec.name', value = 'UnauthorizedTargetUrlSpec')
    @Secured('isAuthenticated()')
    @Controller('/foo')
    static class SecuredController {

        @Get("/bar")
        Map<String, Object> index() {
            [:]
        }
    }

    @Requires(property = 'spec.name', value = 'UnauthorizedTargetUrlSpec')
    @Controller('/login')
    static class LoginController {

        @Get("/auth")
        Map<String, Object> auth() {
            [:]
        }
    }
}

