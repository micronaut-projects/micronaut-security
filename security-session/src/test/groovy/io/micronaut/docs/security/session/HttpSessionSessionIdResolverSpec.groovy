package io.micronaut.docs.security.session

import io.micronaut.context.BeanContext
import io.micronaut.context.annotation.Property
import io.micronaut.core.util.StringUtils
import io.micronaut.security.session.HttpSessionSessionIdResolver
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "micronaut.security.sessionid-resolver.httpsession-id.enabled", value = StringUtils.FALSE)
@MicronautTest(startApplication = false)
class HttpSessionSessionIdResolverSpec extends Specification  {

    @Inject
    BeanContext beanContext

    void "it is possible to disable JsonWebTokenIdSessionIdResolver"() {
        expect:
        !beanContext.containsBean(HttpSessionSessionIdResolver)
    }
}