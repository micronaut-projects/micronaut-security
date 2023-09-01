package io.micronaut.security.token.jwt.endpoints

import io.micronaut.security.endpoints.TokenRefreshRequest
import io.micronaut.serde.ObjectMapper
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@MicronautTest(startApplication = false)
class SerdeSpec extends Specification {

    @Inject
    ObjectMapper objectMapper

    void "TokenRefreshRequest should be Serializable and Deserializable with Serde"() {
        given:
        String json = "{\"grant_type\":\"refresh_token\",\"refresh_token\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbkBsb2NhbC5jb20iLCJjb250ZW50LWxlbmd0aCI6IjEwNSIsInByb2R1Y3QiOiJwcm9kdWN0IiwibmJmIjoxNjU5MDc4ODcwLCJyb2xlcyI6W10sImlzcyI6InRlc3RhcHBsaWNhdGlvbiIsImhvc3QiOiJsb2NhbGhvc3Q6NTQ3MjUiLCJjb25uZWN0aW9uIjoiY2xvc2UiLCJjb250ZW50LXR5cGUiOiJhcHBsaWNhdGlvblwvanNvbiIsImV4cCI6MTY1OTA4MjQ3MCwiaWF0IjoxNjU5MDc4ODcwfQ.ugdU-pYUgwU44Skd2jmP4x_aNLAVhrIuSYwyW21ngAg\"}"

        when:
        TokenRefreshRequest tokenRefreshRequest = new TokenRefreshRequest(TokenRefreshRequest.GRANT_TYPE_REFRESH_TOKEN,
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbkBsb2NhbC5jb20iLCJjb250ZW50LWxlbmd0aCI6IjEwNSIsInByb2R1Y3QiOiJwcm9kdWN0IiwibmJmIjoxNjU5MDc4ODcwLCJyb2xlcyI6W10sImlzcyI6InRlc3RhcHBsaWNhdGlvbiIsImhvc3QiOiJsb2NhbGhvc3Q6NTQ3MjUiLCJjb25uZWN0aW9uIjoiY2xvc2UiLCJjb250ZW50LXR5cGUiOiJhcHBsaWNhdGlvblwvanNvbiIsImV4cCI6MTY1OTA4MjQ3MCwiaWF0IjoxNjU5MDc4ODcwfQ.ugdU-pYUgwU44Skd2jmP4x_aNLAVhrIuSYwyW21ngAg"
                )
        String result = objectMapper.writeValueAsString(tokenRefreshRequest)

        then:
        json == result

        when:
        tokenRefreshRequest = objectMapper.readValue(json, TokenRefreshRequest)

        then:
        tokenRefreshRequest
        tokenRefreshRequest.refreshToken
    }
}
