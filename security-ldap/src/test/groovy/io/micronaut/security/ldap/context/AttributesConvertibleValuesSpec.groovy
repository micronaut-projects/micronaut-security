package io.micronaut.security.ldap.context

import spock.lang.Specification

import javax.naming.directory.Attributes

class AttributesConvertibleValuesSpec extends Specification {

    void "AttributesConvertibleValues does not raise NPE if attribute does not exist"() {
        given:
        def attrs = Stub(Attributes) {
            get(_) >> null
        }
        AttributesConvertibleValues values = new AttributesConvertibleValues(attrs)

        when:
        Optional opt = values.get('foo', null)

        then:
        noExceptionThrown()
        !opt.isPresent()
    }
}
