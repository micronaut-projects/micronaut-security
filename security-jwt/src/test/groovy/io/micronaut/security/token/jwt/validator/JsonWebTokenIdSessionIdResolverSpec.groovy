package io.micronaut.security.token.jwt.validator

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.core.util.StringUtils
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "micronaut.security.sessionid-resolver.jwt-id.enabled", value = StringUtils.FALSE)
@MicronautTest(startApplication = false)
class JsonWebTokenIdSessionIdResolverSpec extends Specification  {

    @Inject
    BeanContext beanContext

    void "it is possible to disable JsonWebTokenIdSessionIdResolver"() {
        expect:
        !beanContext.containsBean(JsonWebTokenIdSessionIdResolver)
    }
}