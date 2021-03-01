package io.micronaut.security.token.jwt.validator

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.reactivex.Flowable
import spock.lang.Specification

import java.util.Date

class NotBeforeJwtClaimsValidatorSpec extends Specification {

    long anHour = 60 * 60 * 1000
    long nextHour = new Date().getTime() + anHour;
    long lastHour = new Date().getTime() - anHour;

    Date future = new Date(nextHour)
    Date past = new Date(lastHour)

    void "not-before claim valid if not-before date is in the past"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (NotBeforeJwtClaimsValidator.NOT_BEFORE_PROP): 'true'
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.NOT_BEFORE)      : past
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

    void "not-before claim is not valid if not-before date is in the future"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (NotBeforeJwtClaimsValidator.NOT_BEFORE_PROP): 'true'
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.NOT_BEFORE)      : future
        ];
        String jwt = jwtGenerator.generateToken(claims).get()

        when:
        Authentication result = Flowable.fromPublisher(jwtValidator.validateToken(jwt, null)).blockingFirst(null)

        then:
        !result

        cleanup:
        context.close()
    }

    void "not-before claim is valid if token does not contain a not-before claim"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (NotBeforeJwtClaimsValidator.NOT_BEFORE_PROP): 'true'
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice'
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

    void "not-before claim is ignored if configuration prop not explicitly set to true"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.NOT_BEFORE)      : future
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
}
