package io.micronaut.security.token.validator

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.core.util.StringUtils
import io.micronaut.security.token.jwt.nimbus.NimbusJsonWebTokenValidator
import io.micronaut.security.token.jwt.nimbus.NimbusReactiveJsonWebTokenValidator
import io.micronaut.security.token.jwt.validator.JsonWebTokenValidator
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.micronaut.security.token.jwt.validator.ReactiveJsonWebTokenValidator
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification


@MicronautTest(startApplication = false, rebuildContext = true)
class TokenValidatorSpec extends Specification {

    @Inject
    Collection<TokenValidator> tokenValidators

    @Inject
    BeanContext beanContext

    void "JwtTokenValidator should not be considered a bean by default"() {
        expect:
        tokenValidators.stream().noneMatch {it instanceof JwtTokenValidator}
    }

    void "NimbusReactiveJsonWebTokenValidator should be considered a bean by default"() {
        expect:
        tokenValidators.size() == 1
        tokenValidators.stream().anyMatch {it.getClass().getSimpleName() == "NimbusReactiveJsonWebTokenValidator"}
    }

    @Property(name = "micronaut.security.token.jwt.nimbus.reactive-validator", value = StringUtils.FALSE)
    void "NimbusReactiveJsonWebTokenValidator can be disabled via config"() {
        expect:
        tokenValidators.stream().noneMatch {it.getClass().getSimpleName() == "NimbusReactiveJsonWebTokenValidator"}
        !beanContext.containsBean(ReactiveJsonWebTokenValidator)
        !beanContext.containsBean(NimbusReactiveJsonWebTokenValidator)
        beanContext.containsBean(JsonWebTokenValidator)
    }

    @Property(name = "micronaut.security.token.jwt.nimbus.validator", value = StringUtils.FALSE)
    void "NimbusJsonWebTokenValidator can be disabled via config"() {
        expect:
        !beanContext.containsBean(JsonWebTokenValidator)
        !beanContext.containsBean(NimbusJsonWebTokenValidator)
        beanContext.containsBean(ReactiveJsonWebTokenValidator)
    }
}
