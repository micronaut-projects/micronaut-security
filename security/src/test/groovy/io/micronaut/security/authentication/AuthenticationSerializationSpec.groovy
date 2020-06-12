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
        UserDetails userDetails = new UserDetails("john", ["X", "Y"], [attr1: 1, attr2: 2])
        byte[] data = serializer.serialize(new AuthenticationUserDetailsAdapter(userDetails, "roles", "sub")).get()
        Authentication deserialized = serializer.deserialize(data, Authentication).get()

        then:
        deserialized.name == "john"
        deserialized.attributes.roles == ["X", "Y"]
        deserialized.attributes.attr1 == 1
        deserialized.attributes.attr2 == 2

        when:
        data = serializer.serialize(new DefaultAuthentication("john", [roles: ["X", "Y"], attr1: 1, attr2: 2])).get()
        deserialized = serializer.deserialize(data, Authentication).get()

        then:
        deserialized.name == "john"
        deserialized.attributes.roles == ["X", "Y"]
        deserialized.attributes.attr1 == 1
        deserialized.attributes.attr2 == 2
    }

    void "test authentication is serializable to json"() {
        ObjectMapper objectMapper = new ObjectMapper()
        objectMapper.registerModule(new SecurityJacksonModule())
        JacksonObjectSerializer serializer = new JacksonObjectSerializer(objectMapper)

        when:
        UserDetails userDetails = new UserDetails("john", ["X", "Y"], [attr1: 1, attr2: 2])
        byte[] data = serializer.serialize(new AuthenticationUserDetailsAdapter(userDetails, "roles", "sub")).get()
        Authentication deserialized = serializer.deserialize(data, Authentication).get()

        then:
        deserialized.name == "john"
        deserialized.attributes.roles == ["X", "Y"]
        deserialized.attributes.attr1 == 1
        deserialized.attributes.attr2 == 2

        when:
        data = serializer.serialize(new DefaultAuthentication("john", [roles: ["X", "Y"], attr1: 1, attr2: 2])).get()
        deserialized = serializer.deserialize(data, Authentication).get()

        then:
        deserialized.name == "john"
        deserialized.attributes.roles == ["X", "Y"]
        deserialized.attributes.attr1 == 1
        deserialized.attributes.attr2 == 2
    }
}
