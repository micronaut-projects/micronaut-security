package io.micronaut.security.token.jwt.validator

import edu.umd.cs.findbugs.annotations.Nullable
import io.micronaut.context.ApplicationContext
import io.micronaut.core.annotation.NonNull
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.reactivex.Flowable
import spock.lang.Shared
import spock.lang.Specification

class IssuerJwtClaimsValidatorSpec extends Specification {

    @Shared
    String expectedIssuer = "expected-issuer"

    @Shared
    String anotherIssuer = "a-different-issuer"

    @Shared
    Map<String, Object> configuration = [
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
    ]

    void "ignores issuer validation if issuer configuration property is not set"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration)
        String jwt = generateJwtWithIssuer(context, anotherIssuer)

        when:
        Authentication result = authenticate(context, jwt)
        then:
        result
        result.attributes[JwtClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }

    void "issuer is valid when issuer claim equals configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            (IssuerJwtClaimsValidator.ISSUER_PROP): expectedIssuer
        ])
        String jwt = generateJwtWithIssuer(context, expectedIssuer)

        when:
        Authentication result = authenticate(context, jwt)

        then:
        result
        result.attributes[JwtClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }

    void "issuer is not valid when issuer claim does not equal configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            (IssuerJwtClaimsValidator.ISSUER_PROP): expectedIssuer
        ])
        String jwt = generateJwtWithIssuer(context, anotherIssuer)

        when:
        Authentication result = authenticate(context, jwt)

        then:
        !result

        cleanup:
        context.close()
    }

    void "issuer is not valid when JWT does not have issuer claim and issuer configuration property exists"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            (IssuerJwtClaimsValidator.ISSUER_PROP): expectedIssuer
        ])
        String jwt = generateJwtWithIssuer(context, null)

        when:
        Authentication result = authenticate(context, jwt)

        then:
        !result

        cleanup:
        context.close()
    }

    @Nullable
    private static Authentication authenticate(@NonNull ApplicationContext context, @NonNull String jwt) {
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class)
        Flowable.fromPublisher(jwtValidator.validateToken(jwt, null)).blockingFirst(null)
    }

    @NonNull
    private static String generateJwtWithIssuer(ApplicationContext context, @Nullable Object issuer) {
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        Map<String, Object> claims = [:]
        claims[JwtClaims.SUBJECT] = 'alice'
        if (issuer != null) {
            claims[JwtClaims.ISSUER] = issuer
        }
        jwtGenerator.generateToken(claims).get()
    }
}
