package io.micronaut.security.token.paseto.validator.claims

import io.micronaut.context.ApplicationContext
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.paseto.generator.PasetoTokenGenerator
import io.micronaut.security.token.paseto.generator.claims.PasetoClaims
import io.micronaut.security.token.paseto.validator.PasetoTokenValidator
import reactor.core.publisher.Flux
import spock.lang.Shared
import spock.lang.Specification

import java.time.Instant

class NotBeforePasetoClaimsValidatorSpec extends Specification {
    @Shared
    long anHour = 60 * 60

    @Shared
    long nextHour = Instant.now().getEpochSecond() + anHour

    @Shared
    Instant future = Instant.ofEpochSecond(nextHour)

    @Shared
    long lastHour = Instant.now().getEpochSecond() - anHour

    @Shared
    Instant past = Instant.ofEpochSecond(lastHour)

    void "not-before claim valid if not-before date is in the past"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                'micronaut.security.token.paseto.config.purpose'              : 'local',
                'micronaut.security.token.paseto.config.secretKey'            : 'dGhpc0lzTXlTZWNyZXQ=',
                'micronaut.security.token.paseto.claims-validators.not-before': 'true'
        ])
        String paseto = generatePasetoWithNotBefore(context, past)

        when:
        Authentication result = authenticate(context, paseto)

        then:
        result
        result.attributes[PasetoClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }

    void "not-before claim is not valid if not-before date is in the future"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                'micronaut.security.token.paseto.config.purpose'              : 'local',
                'micronaut.security.token.paseto.config.secretKey'            : 'dGhpc0lzTXlTZWNyZXQ=',
                'micronaut.security.token.paseto.claims-validators.not-before': 'true'
        ])
        String paseto = generatePasetoWithNotBefore(context, future)

        when:
        Authentication result = authenticate(context, paseto)

        then:
        !result

        cleanup:
        context.close()
    }

    void "not-before claim is valid if token does not contain a not-before claim"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                'micronaut.security.token.paseto.config.purpose'              : 'local',
                'micronaut.security.token.paseto.config.secretKey'            : 'dGhpc0lzTXlTZWNyZXQ=',
                'micronaut.security.token.paseto.claims-validators.not-before': 'true'
        ])
        String paseto = generatePasetoWithNotBefore(context, null)

        when:
        Authentication result = authenticate(context, paseto)

        then:
        result
        result.attributes[PasetoClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }

    void "not-before claim ignored if configuration prop not explicitly set to true"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                'micronaut.security.token.paseto.config.purpose'  : 'local',
                'micronaut.security.token.paseto.config.secretKey': 'dGhpc0lzTXlTZWNyZXQ='
        ])
        String paseto = generatePasetoWithNotBefore(context, past)

        when:
        Authentication result = authenticate(context, paseto)

        then:
        result
        result.attributes[PasetoClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }


    @Nullable
    private static Authentication authenticate(@NonNull ApplicationContext context, @NonNull String paseto) {
        PasetoTokenValidator pasetoTokenValidator = context.getBean(PasetoTokenValidator.class)
        Flux.from(pasetoTokenValidator.validateToken(paseto, null)).blockFirst()
    }


    @NonNull
    private static String generatePasetoWithNotBefore(ApplicationContext context, @Nullable Object notBefore) {
        PasetoTokenGenerator pasetoTokenGenerator = context.getBean(PasetoTokenGenerator.class)
        Map<String, Object> claims = [:]
        claims[PasetoClaims.SUBJECT] = 'alice'
        if (notBefore != null) {
            claims[PasetoClaims.NOT_BEFORE] = notBefore
        }
        pasetoTokenGenerator.generateToken(claims).get()
    }
}
