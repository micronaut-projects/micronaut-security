package io.micronaut.security.token.jwt.validator

import io.micronaut.core.annotation.Nullable
import io.micronaut.context.ApplicationContext
import io.micronaut.core.annotation.NonNull
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import reactor.core.publisher.Flux
import spock.lang.Shared
import spock.lang.Specification

class NotBeforeJwtClaimsValidatorSpec extends Specification {

    @Shared
    long anHour = 60 * 60 * 1000

    @Shared
    long nextHour = new Date().getTime() + anHour;

    @Shared
    Date future = new Date(nextHour)

    @Shared
    long lastHour = new Date().getTime() - anHour;

    @Shared
    Date past = new Date(lastHour)

    @Shared
    Map<String, Object> configuration = [
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
    ]

    void "not-before claim valid if not-before date is in the past"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            'micronaut.security.token.jwt.claims-validators.not-before': 'true'
        ])
        String jwt = generateJwtWithNotBefore(context, past)

        when:
        Authentication result = authenticate(context, jwt)

        then:
        result
        result.attributes[JwtClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }

    void "not-before claim is not valid if not-before date is in the future"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            'micronaut.security.token.jwt.claims-validators.not-before': 'true'
        ])
        String jwt = generateJwtWithNotBefore(context, future)

        when:
        Authentication result = authenticate(context, jwt)

        then:
        !result

        cleanup:
        context.close()
    }

    void "not-before claim is valid if token does not contain a not-before claim"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            'micronaut.security.token.jwt.claims-validators.not-before': 'true'
        ])
        String jwt = generateJwtWithNotBefore(context, null)

        when:
        Authentication result = authenticate(context, jwt)

        then:
        result
        result.attributes[JwtClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }

    void "not-before claim is ignored if configuration prop not explicitly set to true"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration)
        String jwt = generateJwtWithNotBefore(context, future)

        when:
        Authentication result = authenticate(context, jwt)

        then:
        result
        result.attributes[JwtClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }

    @Nullable
    private static Authentication authenticate(@NonNull ApplicationContext context, @NonNull String jwt) {
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Flux.from(jwtValidator.validateToken(jwt, null)).blockFirst()
    }

    @NonNull
    private static String generateJwtWithNotBefore(ApplicationContext context, @Nullable Object notBefore) {
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        Map<String, Object> claims = [:]
        claims[JwtClaims.SUBJECT] = 'alice'
        if (notBefore != null) {
            claims[JwtClaims.NOT_BEFORE] = notBefore
        }
        jwtGenerator.generateToken(claims).get()
    }
}
