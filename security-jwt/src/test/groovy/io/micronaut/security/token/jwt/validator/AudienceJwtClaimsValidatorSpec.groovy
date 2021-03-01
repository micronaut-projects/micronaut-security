package io.micronaut.security.token.jwt.validator

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.reactivex.Flowable
import spock.lang.Specification

class AudienceJwtClaimsValidatorSpec extends Specification {

    String expectedAudience = "expected-audience"
    String anotherAudience = "a-different-audience"
    String yetAnotherAudience = "yet-another-audience"

    void "ignores audience validation if audience configuration property is not set"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.AUDIENCE)        : [anotherAudience, yetAnotherAudience]
        ];
        String jwt = jwtGenerator.generateToken(claims).get()

        when:
        Authentication result = Flowable.fromPublisher(jwtValidator.validateToken(jwt, null)).blockingFirst(null)

        then:
        result
        result.getAttributes().get(JwtClaims.SUBJECT).equals("alice")

        cleanup:
        context.close()
    }

    void "audience is valid when audience claim contains configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (AudienceJwtClaimsValidator.AUDIENCE_PROP): expectedAudience
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.AUDIENCE)        : [anotherAudience, expectedAudience, yetAnotherAudience]
        ];
        String jwt = jwtGenerator.generateToken(claims).get()

        when:
        Authentication result = Flowable.fromPublisher(jwtValidator.validateToken(jwt, null)).blockingFirst(null)

        then:
        result
        result.getAttributes().get(JwtClaims.SUBJECT).equals("alice")

        cleanup:
        context.close()
    }

    void "audience is valid when audience claim is not a list and matches configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (AudienceJwtClaimsValidator.AUDIENCE_PROP): expectedAudience
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.AUDIENCE)        : expectedAudience
        ];
        String jwt = jwtGenerator.generateToken(claims).get()

        when:
        Authentication result = Flowable.fromPublisher(jwtValidator.validateToken(jwt, null)).blockingFirst(null)

        then:
        result
        result.getAttributes().get(JwtClaims.SUBJECT).equals("alice")

        cleanup:
        context.close()
    }

    void "audience is not valid when audience claim does not contain configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (AudienceJwtClaimsValidator.AUDIENCE_PROP): expectedAudience
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.AUDIENCE)        : [anotherAudience, yetAnotherAudience]
        ];
        String jwt = jwtGenerator.generateToken(claims).get()

        when:
        Authentication result = Flowable.fromPublisher(jwtValidator.validateToken(jwt, null)).blockingFirst(null)

        then:
        !result

        cleanup:
        context.close()
    }

    void "audience is not valid when audience claim is not a list and does not equal configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (AudienceJwtClaimsValidator.AUDIENCE_PROP): expectedAudience
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.AUDIENCE)        : anotherAudience
        ];
        String jwt = jwtGenerator.generateToken(claims).get()

        when:
        Authentication result = Flowable.fromPublisher(jwtValidator.validateToken(jwt, null)).blockingFirst(null)

        then:
        !result

        cleanup:
        context.close()
    }

    void "audience is not valid when property configured and token does not include an audience claim"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (AudienceJwtClaimsValidator.AUDIENCE_PROP): expectedAudience
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
        ];
        String jwt = jwtGenerator.generateToken(claims).get()

        when:
        Authentication result = Flowable.fromPublisher(jwtValidator.validateToken(jwt, null)).blockingFirst(null)

        then:
        !result

        cleanup:
        context.close()
    }
}
