package io.micronaut.security.token.jwt.nimbus

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
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
 * With no signature configuration, {@link io.micronaut.security.token.jwt.generator.JwtTokenGenerator} emits unsigned
 * JWTs (alg=none). Because such tokens can be forged by anyone, the validators must reject them by default.
 */
class UnsignedJwtRejectedByDefaultSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'UnsignedJwtRejectedByDefaultSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'bearer',
        ]
    }

    void "accept-unsigned-tokens defaults to false and no signature configuration is present"() {
        expect:
        !applicationContext.getBean(JwtConfiguration).acceptUnsignedTokens
        applicationContext.getBeansOfType(SignatureConfiguration).isEmpty()
    }

    void "an unsigned token issued by login is rejected by default"() {
        when:
        HttpResponse<BearerAccessRefreshToken> loginRsp = client.exchange(HttpRequest.POST('/login', new UsernamePasswordCredentials('sherlock', 'password')), BearerAccessRefreshToken)

        then:
        loginRsp.status() == HttpStatus.OK
        String accessToken = loginRsp.body().accessToken
        accessToken

        and: 'the generator emitted an unsigned token'
        JWTParser.parse(accessToken) instanceof PlainJWT

        when:
        client.exchange(HttpRequest.GET('/secured').bearerAuth(accessToken), String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        and: 'both validators reject it'
        !applicationContext.getBean(JsonWebTokenValidator).validate(accessToken, null).isPresent()
        !Mono.from(applicationContext.getBean(ReactiveJsonWebTokenValidator).validate(accessToken, null)).blockOptional().isPresent()
    }

    void "a forged alg=none token is rejected by default"() {
        given:
        String forged = new PlainJWT(new JWTClaimsSet.Builder()
                .subject('admin')
                .claim('roles', ['ROLE_ADMIN'])
                .build()).serialize()

        when:
        client.exchange(HttpRequest.GET('/secured').bearerAuth(forged), String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        when:
        client.exchange(HttpRequest.GET('/admin').bearerAuth(forged), String)

        then:
        e = thrown()
        e.status == HttpStatus.UNAUTHORIZED
    }

    @Requires(property = 'spec.name', value = 'UnsignedJwtRejectedByDefaultSpec')
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = 'spec.name', value = 'UnsignedJwtRejectedByDefaultSpec')
    @Controller
    static class SecuredController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get('/secured')
        String secured() {
            'secured'
        }

        @Secured('ROLE_ADMIN')
        @Get('/admin')
        String admin() {
            'admin'
        }
    }
}
