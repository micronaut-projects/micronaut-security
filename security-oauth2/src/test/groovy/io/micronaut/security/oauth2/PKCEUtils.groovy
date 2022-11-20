package io.micronaut.security.oauth2

class PKCEUtils {

    static String getCodeChallenge(Map<String, String> queryValues) {
        return queryValues['code_challenge']
    }

    static String getCodeChallengeMethod(Map<String, String> queryValues) {
        return queryValues['code_challenge_method']
    }
}
