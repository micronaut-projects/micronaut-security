package io.micronaut.security.oauth2

class StateUtils {

    private static final String QUESTION_MARK = '?'
    static String decodeState(Map<String, String> queryValues) {
        new String(Base64.getUrlDecoder().decode(queryValues['state']))
    }

    static Map<String, String> queryValuesAsMap(String location) {
        List<String> arr = location.split("&") as List<String>
        Map<String, String> result = [:]
        arr.collect { el ->
            List<String> subArr = el.split("=") as List<String>

            String key =  subArr[0]
            if (key.contains(QUESTION_MARK)) {
                key = key.substring(key.indexOf(QUESTION_MARK) + QUESTION_MARK.length())
            }
            Map<String, String> m = [:]
            m.put(key, subArr[1])
            m
        }.each { result << it }

        result
    }
}
