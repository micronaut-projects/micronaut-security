package io.micronaut.security.authentication

import com.fasterxml.jackson.databind.ObjectMapper
import io.micronaut.core.serialize.JdkSerializer
import io.micronaut.jackson.serialize.JacksonObjectSerializer
import io.micronaut.security.authentication.jackson.SecurityJacksonModule
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
        ObjectMapper objectMapper = new ObjectMapper()
        objectMapper.registerModule(new SecurityJacksonModule())
        JacksonObjectSerializer serializer = new JacksonObjectSerializer(objectMapper)

        when:
        //this represents the claims that will be set by the server
        Authentication authentication = new ClientAuthentication("john", [attr1: 1, attr2: 2, rolesKey: "roles", "roles": ["X", "Y"]])
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
