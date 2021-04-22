package io.micronaut.security.token.jwt.validator

import io.micronaut.core.annotation.Nullable
import io.micronaut.context.ApplicationContext
import io.micronaut.core.annotation.NonNull
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.reactivex.Flowable
import spock.lang.Shared
import spock.lang.Specification

class AudienceJwtClaimsValidatorSpec extends Specification {

    @Shared
    String expectedAudience = "expected-audience"

    @Shared
    String anotherAudience = "a-different-audience"

    @Shared
    String yetAnotherAudience = "yet-another-audience"

    @Shared
    Map<String, Object> configuration = [
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
    ]

    void "ignores audience validation if audience configuration property is not set"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration)
        String jwt = generateJwtWithAudiences(context, [anotherAudience, yetAnotherAudience])

        when:
        Authentication result = authenticate(context, jwt)

        then:
        result
        result.attributes[JwtClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }

    void "audience is valid when audience claim contains configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            'micronaut.security.token.jwt.claims-validators.audience': expectedAudience
        ])
        String jwt = generateJwtWithAudiences(context, [anotherAudience, expectedAudience, yetAnotherAudience])


        when:
        Authentication result = authenticate(context, jwt)

        then:
        result
        result.attributes[JwtClaims.SUBJECT] == "alice"

        cleanup:
        context.close()
    }

    void "audience is valid when audience claim is not a list and matches configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            'micronaut.security.token.jwt.claims-validators.audience': expectedAudience
        ])
        String jwt = generateJwtWithAudiences(context, expectedAudience)

        when:
        Authentication result = authenticate(context, jwt)

        then:
        result
        result.attributes[JwtClaims.SUBJECT] == "alice"
        cleanup:
        context.close()
    }

    void "audience is not valid when audience claim does not contain configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            'micronaut.security.token.jwt.claims-validators.audience': expectedAudience
        ])
        String jwt = generateJwtWithAudiences(context, [anotherAudience, yetAnotherAudience])

        when:
        Authentication result = authenticate(context, jwt)

        then:
        !result

        cleanup:
        context.close()
    }

    void "audience is not valid when audience claim is not a list and does not equal configuration property"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            'micronaut.security.token.jwt.claims-validators.audience': expectedAudience
        ])
        String jwt = generateJwtWithAudiences(context, anotherAudience)

        when:
        Authentication result = authenticate(context, jwt)

        then:
        !result

        cleanup:
        context.close()
    }

    void "audience is not valid when property configured and token does not include an audience claim"() {
        given:
        ApplicationContext context = ApplicationContext.run(configuration + [
            'micronaut.security.token.jwt.claims-validators.audience': expectedAudience
        ])
        String jwt = generateJwtWithAudiences(context, null)

        when:
        Authentication result = authenticate(context ,jwt)

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
    private static String generateJwtWithAudiences(ApplicationContext context, @Nullable Object audience) {
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class)
        Map<String, Object> claims = [:]
        claims[JwtClaims.SUBJECT] = 'alice'
        if (audience != null) {
            claims[JwtClaims.AUDIENCE] = audience
        }
        jwtGenerator.generateToken(claims).get()
    }
}
