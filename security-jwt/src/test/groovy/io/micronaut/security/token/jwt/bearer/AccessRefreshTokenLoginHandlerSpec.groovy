package io.micronaut.security.token.jwt.bearer

import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.testutils.EmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.Unroll

import javax.inject.Singleton

class AccessRefreshTokenLoginHandlerSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'AccessRefreshTokenLoginHandlerSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                'micronaut.security.authentication'   : 'bearer',
        ]
    }

    @Unroll
    void "test invalid authentication with username #username"() {
        expect:
        applicationContext.getBean(SignatureConfiguration.class)

        when:
        applicationContext.getBean(EncryptionConfiguration.class)

        then:
        thrown(NoSuchBeanException)

        when:
        def creds = new UsernamePasswordCredentials(username, password)
        client.exchange(HttpRequest.POST('/login', creds))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
        e.message == message

        where:
        username          | password  | message
        "notFound"        | "valid"   | "User Not Found"
        "valid"           | "invalid" | "Credentials Do Not Match"
        "disabled"        | "valid"   | "User Disabled"
        "accountExpired"  | "valid"   | "Account Expired"
        "passwordExpired" | "valid"   | "Password Expired"
        "accountLocked"   | "valid"   | "Account Locked"
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'AccessRefreshTokenLoginHandlerSpec')
    static class TestingAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {

            return Flowable.create({ emitter ->
                String username = authenticationRequest.getIdentity().toString()
                switch (username) {
                    case "disabled":
                        emitter.onNext(new AuthenticationFailed(AuthenticationFailureReason.USER_DISABLED))
                        emitter.onComplete()
                        break
                    case "accountExpired":
                        emitter.onNext(new AuthenticationFailed(AuthenticationFailureReason.ACCOUNT_EXPIRED))
                        emitter.onComplete()
                        break
                    case "passwordExpired":
                        emitter.onNext(new AuthenticationFailed(AuthenticationFailureReason.PASSWORD_EXPIRED))
                        emitter.onComplete()
                        break
                    case "accountLocked":
                        emitter.onNext(new AuthenticationFailed(AuthenticationFailureReason.ACCOUNT_LOCKED))
                        emitter.onComplete()
                        break
                    case "invalidPassword":
                        emitter.onNext(new AuthenticationFailed(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH))
                        emitter.onComplete()
                        break
                    case "notFound":
                        emitter.onNext(new AuthenticationFailed(AuthenticationFailureReason.USER_NOT_FOUND))
                        emitter.onComplete()
                        break
                }
                if (authenticationRequest.getSecret().toString() == "invalid") {
                    emitter.onNext(new AuthenticationFailed(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH))
                    emitter.onComplete()
                } else {
                    emitter.onNext(new UserDetails(username, (username == "admin") ? ["ROLE_ADMIN"] : ["foo", "bar"]))
                    emitter.onComplete()
                }
            }, BackpressureStrategy.ERROR)
        }
    }
}
