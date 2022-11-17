package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.core.util.StringUtils
import io.micronaut.security.testutils.ApplicationContextSpecification

class PKCEFactorySpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.pkce.enabled': StringUtils.TRUE
        ]
    }

    void "when pkce is enabled a bean of Type PKCEFactory exists"() {
        expect:
        applicationContext.containsBean(PKCEFactory)
    }
}
