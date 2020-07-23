package io.micronaut.docs.security.principalparam


import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.security.EmbeddedServerSpecification

class UserControllerSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        "principalparam"
    }

    def "verify you can use java.security.Principal as controller parameter to get the logged in user"() {
        when:
        HttpRequest request = HttpRequest.GET("/user/myinfo")
        HttpResponse<Map> rsp = client.exchange(request, Map)

        then:
        rsp.status() == HttpStatus.OK
        !rsp.body().containsKey('username')

        when:
        String username = 'user'
        String password = 'password'
        String encoded = "$username:$password".bytes.encodeBase64()
        String authorization = "Basic $encoded".toString()
        request = HttpRequest.GET("/user/myinfo").header("Authorization", authorization)
        rsp = client.exchange(request, Map)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().containsKey('username')
        rsp.body()['username'] == 'user'
    }
}
