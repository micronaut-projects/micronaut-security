package io.micronaut.security.token.jwt.validator

import com.nimbusds.jwt.JWTClaimsSet
import io.micronaut.context.ApplicationContext
import spock.lang.Specification

import java.time.Duration

class ClockSkewJwtClaimsValidatorSpec extends Specification {

    private static final Map<String, Object> BASE_CONFIG = [
            'spec.name'                                                 : ClockSkewJwtClaimsValidatorSpec.simpleName,
            'micronaut.security.token.jwt.claims-validators.not-before': true,
    ]

    void "clock skew defaults to zero"() {
        given:
        ApplicationContext context = ApplicationContext.run(BASE_CONFIG)

        expect:
        context.getBean(JwtClaimsValidatorConfiguration).clockSkew == Duration.ZERO

        cleanup:
        context.close()
    }

    void "negative clock skew is treated as zero"() {
        given:
        ApplicationContext context = ApplicationContext.run(BASE_CONFIG + [
                'micronaut.security.token.jwt.claims-validators.clock-skew': '-30s'
        ])

        expect:
        context.getBean(JwtClaimsValidatorConfiguration).clockSkew == Duration.ZERO
        !context.getBean(ExpirationJwtClaimsValidator).validate(claimsWithExpiration(-10))
        context.getBean(ExpirationJwtClaimsValidator).validate(claimsWithExpiration(60))

        cleanup:
        context.close()
    }

    void "with the default clock skew expiration and not-before are validated strictly"() {
        given:
        ApplicationContext context = ApplicationContext.run(BASE_CONFIG)
        ExpirationJwtClaimsValidator expirationValidator = context.getBean(ExpirationJwtClaimsValidator)
        NotBeforeJwtClaimsValidator notBeforeValidator = context.getBean(NotBeforeJwtClaimsValidator)

        expect:
        expirationValidator.validate(claimsWithExpiration(60))
        !expirationValidator.validate(claimsWithExpiration(-10))
        !expirationValidator.validate(claimsWithExpiration(-60))

        notBeforeValidator.validate(claimsWithNotBefore(-60))
        !notBeforeValidator.validate(claimsWithNotBefore(10))
        !notBeforeValidator.validate(claimsWithNotBefore(60))

        cleanup:
        context.close()
    }

    void "expiration validation tolerates the configured clock skew"() {
        given:
        ApplicationContext context = ApplicationContext.run(BASE_CONFIG + [
                'micronaut.security.token.jwt.claims-validators.clock-skew': '30s'
        ])
        ExpirationJwtClaimsValidator validator = context.getBean(ExpirationJwtClaimsValidator)

        expect:
        context.getBean(JwtClaimsValidatorConfiguration).clockSkew == Duration.ofSeconds(30)
        validator.validate(claimsWithExpiration(60))
        validator.validate(claimsWithExpiration(-10))
        !validator.validate(claimsWithExpiration(-60))

        cleanup:
        context.close()
    }

    void "not-before validation tolerates the configured clock skew"() {
        given:
        ApplicationContext context = ApplicationContext.run(BASE_CONFIG + [
                'micronaut.security.token.jwt.claims-validators.clock-skew': '30s'
        ])
        NotBeforeJwtClaimsValidator validator = context.getBean(NotBeforeJwtClaimsValidator)

        expect:
        validator.validate(claimsWithNotBefore(-60))
        validator.validate(claimsWithNotBefore(10))
        !validator.validate(claimsWithNotBefore(60))

        cleanup:
        context.close()
    }

    void "deprecated no-arg constructors keep strict validation"() {
        expect:
        !new ExpirationJwtClaimsValidator().validate(claimsWithExpiration(-10))
        new ExpirationJwtClaimsValidator().validate(claimsWithExpiration(60))
        !new NotBeforeJwtClaimsValidator().validate(claimsWithNotBefore(10))
        new NotBeforeJwtClaimsValidator().validate(claimsWithNotBefore(-60))
    }

    private static JWTClaimsSet claimsWithExpiration(long secondsFromNow) {
        new JWTClaimsSet.Builder()
                .subject('alice')
                .expirationTime(new Date(System.currentTimeMillis() + (secondsFromNow * 1000)))
                .build()
    }

    private static JWTClaimsSet claimsWithNotBefore(long secondsFromNow) {
        new JWTClaimsSet.Builder()
                .subject('alice')
                .notBeforeTime(new Date(System.currentTimeMillis() + (secondsFromNow * 1000)))
                .build()
    }
}
