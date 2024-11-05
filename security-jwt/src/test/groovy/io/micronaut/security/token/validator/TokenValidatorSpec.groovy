package io.micronaut.security.token.validator

import io.micronaut.context.annotation.Property
import io.micronaut.core.util.StringUtils
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@MicronautTest(startApplication = false, rebuildContext = true)
class TokenValidatorSpec extends Specification {

    @Inject
    Collection<TokenValidator> tokenValidators

    void "JwtTokenValidator should not be considered a bean by default"() {
        expect:
        tokenValidators.stream().noneMatch {it instanceof JwtTokenValidator}
    }

    void "NimbusReactiveJsonWebTokenValidator should be considered a bean by default"() {
        expect:
        tokenValidators.stream().anyMatch {it.getClass().getSimpleName() == "NimbusReactiveJsonWebTokenValidator"}
    }

    @Property(name = "micronaut.security.token.jwt.reactive-validator.enabled", value = StringUtils.FALSE)
    void "NimbusReactiveJsonWebTokenValidator can be disabled via config"() {
        expect:
        tokenValidators.stream().noneMatch {it.getClass().getSimpleName() == "NimbusReactiveJsonWebTokenValidator"}
    }
}
