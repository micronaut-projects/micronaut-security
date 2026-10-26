package io.micronaut.security.jacksondatabind.oauth2;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;

@Property(name = "jackson.bean-introspection-module", value = StringUtils.FALSE)
@MicronautTest(startApplication = false)
class TokenErrorResponseJacksonBeanIntrospectionModuleFalseTest extends AbstractTokenErrorResponseJacksonTest {
}
