package io.micronaut.security.docs.authenticationparam

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import spock.lang.Specification

@Property(name = "spec.name", value = "AuthenticationParamTest")
@MicronautTest
class AuthenticationParamTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "Authentication can be used as a controller parameter to get the logged in user"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpResponse<Map> rsp = client.exchange(HttpRequest.GET("/user/myinfo"), Map)

        then:
        rsp.status() == HttpStatus.OK
        !rsp.body().containsKey('username')

        when:
        rsp = client.exchange(HttpRequest.GET("/user/myinfo").basicAuth("user", "password"), Map)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().containsKey('username')
        rsp.body()['username'] == 'user'
        rsp.body()['roles'] == ['ROLE_USER']
    }

    @Requires(property = "spec.name", value = "AuthenticationParamTest")
    @Singleton
    static class AuthenticationProviderUserPassword<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            (authRequest.identity == "user" && authRequest.secret == "password")
                ? AuthenticationResponse.success("user", ["ROLE_USER"])
                : AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
        }
    }
}
