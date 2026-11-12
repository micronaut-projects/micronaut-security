package io.micronaut.security.token.jwt.nimbus

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.config.JwtConfiguration
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.validator.JsonWebTokenValidator
import io.micronaut.security.token.jwt.validator.ReactiveJsonWebTokenValidator
import io.micronaut.security.token.render.BearerAccessRefreshToken
import jakarta.inject.Singleton
import reactor.core.publisher.Mono

/**
 * Once a signature configuration is present, an unsigned JWT (alg=none) is rejected even if
 * {@code micronaut.security.token.jwt.accept-unsigned-tokens} is true.
 */
class UnsignedJwtRejectedWhenSignatureConfiguredSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'UnsignedJwtRejectedWhenSignatureConfiguredSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'bearer',
                'micronaut.security.token.jwt.accept-unsigned-tokens': true,
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ]
    }

    void "accept-unsigned-tokens is true but a signature configuration is present"() {
        expect:
        applicationContext.getBean(JwtConfiguration).acceptUnsignedTokens
        !applicationContext.getBeansOfType(SignatureConfiguration).isEmpty()
    }

    void "signed tokens issued by login are accepted"() {
        when:
        HttpResponse<BearerAccessRefreshToken> loginRsp = client.exchange(HttpRequest.POST('/login', new UsernamePasswordCredentials('sherlock', 'password')), BearerAccessRefreshToken)

        then:
        loginRsp.status() == HttpStatus.OK
        String accessToken = loginRsp.body().accessToken
        JWTParser.parse(accessToken) instanceof SignedJWT

        when:
        HttpResponse<String> rsp = client.exchange(HttpRequest.GET('/secured').bearerAuth(accessToken), String)

        then:
        rsp.status() == HttpStatus.OK
    }

    void "a forged alg=none token is rejected regardless of accept-unsigned-tokens"() {
        given:
        String forged = new PlainJWT(new JWTClaimsSet.Builder()
                .subject('sherlock')
                .claim('roles', ['ROLE_ADMIN'])
                .build()).serialize()

        when:
        client.exchange(HttpRequest.GET('/secured').bearerAuth(forged), String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        and: 'both validators reject it'
        !applicationContext.getBean(JsonWebTokenValidator).validate(forged, null).isPresent()
        !Mono.from(applicationContext.getBean(ReactiveJsonWebTokenValidator).validate(forged, null)).blockOptional().isPresent()
    }

    @Requires(property = 'spec.name', value = 'UnsignedJwtRejectedWhenSignatureConfiguredSpec')
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = 'spec.name', value = 'UnsignedJwtRejectedWhenSignatureConfiguredSpec')
    @Controller
    static class SecuredController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get('/secured')
        String secured() {
            'secured'
        }
    }
}
