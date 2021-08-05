package io.micronaut.security.authentication

import io.micronaut.core.serialize.JdkSerializer
import spock.lang.Specification

class AuthenticationSerializationSpec extends Specification {

    void "test authentication is serializable"() {
        JdkSerializer serializer = new JdkSerializer()

        when:
        Authentication authentication = Authentication.build("john", ["X", "Y"], [attr1: 1, attr2: 2])
        byte[] data = serializer.serialize(authentication).get()
        Authentication deserialized = serializer.deserialize(data, Authentication).get()

        then:
        deserialized.name == "john"
        deserialized.attributes.attr1 == 1
        deserialized.attributes.attr2 == 2
        deserialized.roles.size() == 2
        deserialized.roles.contains("X")
        deserialized.roles.contains("Y")
    }
}
