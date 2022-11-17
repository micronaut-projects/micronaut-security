package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.context.exceptions.BeanInstantiationException
import io.micronaut.core.util.StringUtils
import io.micronaut.security.testutils.ApplicationContextSpecification

class PKCEConfigurationPersistenceSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.oauth2.pkce.enabled': StringUtils.TRUE,
                'micronaut.security.oauth2.pkce.persistence': 'foo'
        ]
    }

    void "PKCEConfiguration persistence accepts only session and cookie"() {
        when:
        applicationContext.getBean(PKCEConfiguration.class)

        then:
        BeanInstantiationException e = thrown()
        e.message.contains('must match "cookie|session"')
    }
}
