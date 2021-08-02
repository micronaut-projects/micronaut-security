package io.micronaut.security.token.jwt.bearer

import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.FailedAuthenticationScenario
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import jakarta.inject.Singleton
import spock.lang.Unroll

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
    static class TestingAuthenticationProvider extends MockAuthenticationProvider {
        TestingAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('admin',  ["ROLE_ADMIN"])], [
                new FailedAuthenticationScenario("disabled", AuthenticationFailureReason.USER_DISABLED),
                new FailedAuthenticationScenario("accountExpired", AuthenticationFailureReason.ACCOUNT_EXPIRED),
                new FailedAuthenticationScenario("passwordExpired", AuthenticationFailureReason.PASSWORD_EXPIRED),
                new FailedAuthenticationScenario("accountLocked", AuthenticationFailureReason.ACCOUNT_LOCKED),
                new FailedAuthenticationScenario("invalidPassword", AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                new FailedAuthenticationScenario("valid", AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
                new FailedAuthenticationScenario("notFound", AuthenticationFailureReason.USER_NOT_FOUND),
            ])
        }
    }
}
