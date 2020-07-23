package io.micronaut.security.oauth2

class StateUtils {
    static String stateParser(String location) {
        String sublocation = location.substring(location.indexOf('state=') + 'state='.length())
        sublocation = sublocation.substring(0, sublocation.indexOf('&client_id='))
        new String(Base64.getUrlDecoder().decode(sublocation))
    }
}
