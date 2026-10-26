package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.context.exceptions.DisabledBeanException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UserInfoClientFactoryTest {

    @ParameterizedTest
    @CsvSource({
        "https://idp.example.com/userinfo,                     https://idp.example.com,       /userinfo",
        "https://idp.example.com,                              https://idp.example.com,       /",
        "https://idp.example.com/,                             https://idp.example.com,       /",
        "https://userinfo.example.com/userinfo,                https://userinfo.example.com,  /userinfo",
        "https://idp.example.com:8443/v1/userinfo?format=json, https://idp.example.com:8443,  /v1/userinfo?format=json",
        "https://idp.example.com?format=json,                  https://idp.example.com,       /?format=json",
        "http://localhost:8080/oauth2/userinfo,                http://localhost:8080,         /oauth2/userinfo",
        "https://[2001:db8::1]:8443/userinfo,                  https://[2001:db8::1]:8443,    /userinfo",
        "https://[::1]/userinfo,                               https://[::1],                 /userinfo"
    })
    void baseUrlAndPathAreDerivedFromTheUrlComponents(String userInfoEndpoint, String expectedBaseUrl, String expectedPath) {
        UserInfoClientTokenValidatorConfiguration config = UserInfoClientFactory.createUserInfoClientWithUrl(userInfoEndpoint, "idp");
        assertEquals(expectedBaseUrl, config.baseUrl());
        assertEquals(expectedPath, config.path());
        assertEquals("idp", config.name());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void missingUserInfoEndpointDisablesTheBean(String userInfoEndpoint) {
        assertThrows(DisabledBeanException.class, () -> UserInfoClientFactory.createUserInfoClientWithUrl(userInfoEndpoint, "idp"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"userinfo", "idp.example.com/userinfo", "foo://idp.example.com/userinfo", "file:///userinfo"})
    void invalidUserInfoEndpointDisablesTheBean(String userInfoEndpoint) {
        assertThrows(DisabledBeanException.class, () -> UserInfoClientFactory.createUserInfoClientWithUrl(userInfoEndpoint, "idp"));
    }
}
