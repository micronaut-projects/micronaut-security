package io.micronaut.security.supabase.auth;

import io.micronaut.security.authentication.AuthenticationFailureReason;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SupabaseTokenGrantsTest {

    @ParameterizedTest
    @CsvSource({
        "invalid_credentials, CREDENTIALS_DO_NOT_MATCH",
        "invalid_grant, CREDENTIALS_DO_NOT_MATCH",
        "user_not_found, USER_NOT_FOUND",
        "email_not_confirmed, USER_DISABLED",
        "phone_not_confirmed, USER_DISABLED",
        "user_banned, ACCOUNT_LOCKED",
        "over_request_rate_limit, UNKNOWN",
        "validation_failed, UNKNOWN",
    })
    void supabaseErrorCodesMapToFailureReasons(String errorCode, AuthenticationFailureReason expected) {
        assertEquals(expected, SupabaseTokenGrants.failureReason(errorCode));
    }

    @ParameterizedTest
    @NullSource
    void missingErrorCodeIsUnknown(String errorCode) {
        assertEquals(AuthenticationFailureReason.UNKNOWN, SupabaseTokenGrants.failureReason(errorCode));
    }
}
