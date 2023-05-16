package io.micronaut.security.oauth2.endpoint.authorization.response

import io.micronaut.core.convert.value.MutableConvertibleMultiValuesMap
import io.micronaut.security.errors.ErrorCode
import spock.lang.Specification
import spock.lang.Unroll

class DefaultAuthorizationErrorResponseSpec extends Specification {

    @Unroll
    void "test error code not in enum"() {
        given:
        Map<CharSequence, List<String>> values = new HashMap<>()
        values.put("error", Collections.singletonList("user_cancelled_login"))
        values.put("error_description", Collections.singletonList("The user cancelled LinkedIn login"))

        when:
        ErrorCode errorCode = DefaultAuthorizationErrorResponse.getError(new MutableConvertibleMultiValuesMap(values))

        then:
        errorCode.getErrorCode() == 'user_cancelled_login'
        errorCode.getErrorCodeDescription() == 'The user cancelled LinkedIn login'
    }

    @Unroll
    void "test error code is null"() {
        given:
        Map<CharSequence, List<String>> values = new HashMap<>()
        values.put("error_description", Collections.singletonList("The user cancelled LinkedIn login"))

        when:
        ErrorCode errorCode = DefaultAuthorizationErrorResponse.getError(new MutableConvertibleMultiValuesMap(values))

        then:
        errorCode.getErrorCode() == null
        errorCode.getErrorCodeDescription() == 'The user cancelled LinkedIn login'
    }
}
