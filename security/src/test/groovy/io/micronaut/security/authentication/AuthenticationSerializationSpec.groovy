package io.micronaut.security.authentication

import io.micronaut.core.serialize.JdkSerializer
import io.micronaut.serde.ObjectMapper
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

    void "test authentication is serializable to json"() {
        given:
        ObjectMapper objectMapper = ObjectMapper.getDefault()

        when:
        //this represents the claims that will be set by the server
        Authentication authentication = new ClientAuthentication("john", [attr1: 1, attr2: 2, rolesKey: "roles", "roles": ["X", "Y"]])
        String json = objectMapper.writeValueAsString(authentication)
        Authentication deserialized = objectMapper.readValue(json, Authentication)

        then:
        deserialized.name == "john"
        deserialized.attributes.attr1 == 1
        deserialized.attributes.attr2 == 2
        deserialized.roles.size() == 2
        deserialized.roles.contains("X")
        deserialized.roles.contains("Y")
    }

    void "deserialization without attributes"() {
        given:
        ObjectMapper objectMapper = ObjectMapper.getDefault()

        when:
        Authentication deserialized = objectMapper.readValue('{\"name\":\"foo\"}', Authentication)

        then:
        deserialized.name == "foo"
        deserialized.attributes.isEmpty()
    }
}
