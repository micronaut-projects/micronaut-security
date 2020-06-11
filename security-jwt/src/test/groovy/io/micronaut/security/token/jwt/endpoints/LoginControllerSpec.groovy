package io.micronaut.security.token.jwt.endpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.config.TokenConfiguration
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.testutils.EmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

class LoginControllerSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                'micronaut.security.authentication'   : 'bearer',
        ]
    }

    @Override
    String getSpecName() {
        'LoginControllerSpec'
    }

    def "if valid credentials authenticate"() {
        expect:
        applicationContext.getBean(AuthenticationProviderUserPassword.class)
        applicationContext.getBean(SignatureConfiguration.class)
        applicationContext.getBean(SignatureConfiguration.class, Qualifiers.byName("generator"))

        when:
        applicationContext.getBean(EncryptionConfiguration.class)

        then:
        thrown(NoSuchBeanException)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        !rsp.body().refreshToken
        rsp.body().username
        rsp.body().roles == null
        rsp.body().expiresIn
        rsp.body().tokenType
    }

    def "invoking login with GET, returns unauthorized"() {
        expect:
        applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        client.exchange(HttpRequest.GET('/login').body(creds))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    def "if invalid credentials unauthorized"() {
        expect:
        applicationContext.getBean(AuthenticationProviderUserPassword.class)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'bogus')
        client.exchange(HttpRequest.POST('/login', creds))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "attempt to login with bad credentials"() {
        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("notFound", "password")
        client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'LoginControllerSpec')
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {
        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({emitter ->
                if ( authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password' ) {
                    emitter.onNext(AuthenticationResponse.build('user', new TokenConfiguration() {}))

                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }
                emitter.onComplete()

            }, BackpressureStrategy.ERROR)
        }
    }

}
