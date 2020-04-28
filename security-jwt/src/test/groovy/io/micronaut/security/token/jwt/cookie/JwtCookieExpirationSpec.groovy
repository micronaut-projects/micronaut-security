package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.client.RxHttpClient
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.Specification

class JwtCookieExpirationSpec extends Specification {

    void "test max-age is set from jwt cookie settings"() {
        ApplicationContext context = ApplicationContext.run(
                [
                        'spec.name': 'jwtcookie',
                        'micronaut.http.client.followRedirects': false,
                        'micronaut.security.endpoints.login.enabled': true,
                        'micronaut.security.endpoints.logout.enabled': true,
                        'micronaut.security.token.jwt.bearer.enabled': false,
                        'micronaut.security.token.jwt.cookie.enabled': true,
                        'micronaut.security.token.jwt.cookie.cookie-max-age': '5m',
                        'micronaut.security.token.jwt.cookie.login-failure-target-url': '/login/authFailed',
                        'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                ], Environment.TEST)
        EmbeddedServer embeddedServer = context.getBean(EmbeddedServer).start()
        RxHttpClient client = context.createBean(RxHttpClient, embeddedServer.getURL())

        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse loginRsp = client.toBlocking().exchange(loginRequest, String)

        when:
        String cookie = loginRsp.getHeaders().get('Set-Cookie')

        then:
        cookie.contains('Max-Age=300')

        cleanup:
        context.close()
    }


    void "test max-age is set from jwt generator settings"() {
        ApplicationContext context = ApplicationContext.run(
                [
                        'spec.name': 'jwtcookie',
                        'micronaut.http.client.followRedirects': false,
                        'micronaut.security.endpoints.login.enabled': true,
                        'micronaut.security.endpoints.logout.enabled': true,
                        'micronaut.security.token.jwt.bearer.enabled': false,
                        'micronaut.security.token.jwt.cookie.enabled': true,
                        'micronaut.security.token.jwt.cookie.login-failure-target-url': '/login/authFailed',
                        'micronaut.security.token.jwt.generator.access-token.expiration': '500',
                        'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                ], Environment.TEST)
        EmbeddedServer embeddedServer = context.getBean(EmbeddedServer).start()
        RxHttpClient client = context.createBean(RxHttpClient, embeddedServer.getURL())

        HttpRequest loginRequest = HttpRequest.POST('/login', new LoginForm(username: 'sherlock', password: 'password'))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)

        HttpResponse loginRsp = client.toBlocking().exchange(loginRequest, String)

        when:
        String cookie = loginRsp.getHeaders().get('Set-Cookie')

        then:
        cookie.contains('Max-Age=500')

        cleanup:
        context.close()
    }


}
