package io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence

import io.micronaut.core.util.StringUtils
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.cookie.CookiePKCEPersistence
import io.micronaut.security.testutils.ApplicationContextSpecification

class PKCEPersistenceSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.pkce.enabled': StringUtils.TRUE
        ]
    }

    void "when pkce is enabled a bean of Type PKCEPersistenceSpec exists and it defaults to CookiePKCEPersistence"() {
        expect:
        applicationContext.containsBean(PKCEPersistence)

        and: 'and it is cookie by default'
        applicationContext.getBean(PKCEPersistence) instanceof CookiePKCEPersistence
    }
}
