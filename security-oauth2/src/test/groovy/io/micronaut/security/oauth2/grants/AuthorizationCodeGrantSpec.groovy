package io.micronaut.security.oauth2.grants

import io.micronaut.core.beans.BeanIntrospection
import spock.lang.Specification

class AuthorizationCodeGrantSpec extends Specification {

    void "AuthorizationCodeGrant is annotated with Introspected"() {
        when:
        BeanIntrospection.getIntrospection(AuthorizationCodeGrant.class);

        then:
        noExceptionThrown()
    }

    void "AuthorizationCodeGrant::toMap"() {
        given:
        AuthorizationCodeGrant grant = new AuthorizationCodeGrant();
        grant.setCode("xxx");
        grant.setGrantType(GrantType.AUTHORIZATION_CODE.toString());

        expect:
        ['code': 'xxx', 'grant_type': 'authorization_code'] == grant.toMap()
    }
}
