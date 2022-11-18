package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.core.util.StringUtils
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "micronaut.security.oauth2.pkce.enabled", value = StringUtils.TRUE)
@MicronautTest(startApplication = false)
class PkceGeneratorOrderSpec extends Specification {
    @Inject
    BeanContext beanContext

    void "S256 is ordered before plain"() {
        when:
        List<PkceGenerator> pkceGenerators = beanContext.getBeansOfType(PkceGenerator.class)

        then:
        pkceGenerators.size() == 2
        pkceGenerators.get(0) instanceof S256PkceGenerator
        pkceGenerators.get(1) instanceof PlainPkceGenerator
    }
}
