package io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.session

import io.micronaut.core.util.StringUtils
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence
import io.micronaut.security.testutils.ApplicationContextSpecification

class SessionPkcePersistenceSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.session.enabled'        : StringUtils.TRUE,
                'micronaut.security.oauth2.pkce.persistence': 'session',
                'micronaut.security.oauth2.pkce.enabled': StringUtils.TRUE
        ]
    }

    void "PKCEPersistence is an instance of SessionPKCEPersistence"() {
        expect:
        applicationContext.containsBean(PkcePersistence)
        applicationContext.getBean(PkcePersistence) instanceof SessionPkcePersistence
    }
}
