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

class IssuerJwtClaimsValidatorSpec extends Specification {

    String expectedIssuer = "expected-issuer"
    String anotherIssuer = "a-different-issuer"

    void "ignores issuer validation if issuer configuration property is not set"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.ISSUER)          : anotherIssuer
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

    void "issuer is valid when issuer claim equals configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (IssuerJwtClaimsValidator.ISSUER_PROP): expectedIssuer
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.ISSUER)          : expectedIssuer
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

    void "issuer is not valid when issuer claim does not equal configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (IssuerJwtClaimsValidator.ISSUER_PROP): expectedIssuer
        ], Environment.TEST)
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> claims = [
            (JwtClaims.SUBJECT)         : 'alice',
            (JwtClaims.ISSUER)          : anotherIssuer
        ];
        String jwt = jwtGenerator.generateToken(claims).get()

        when:
        Authentication result = Flowable.fromPublisher(jwtValidator.validateToken(jwt, null)).blockingFirst(null)

        then:
        !result

        cleanup:
        context.close()
    }

    void "issuer is not valid when JWT does not have issuer claim and issuer configuration property exists"() {
        given:
        ApplicationContext context = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
            (IssuerJwtClaimsValidator.ISSUER_PROP): expectedIssuer
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
        !result

        cleanup:
        context.close()
    }
}
