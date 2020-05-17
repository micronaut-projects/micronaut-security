package io.micronaut.security.token.jwt

import groovy.transform.CompileStatic
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken

@CompileStatic
trait AuthorizationUtils {

    abstract BlockingHttpClient getClient()

    String loginWith(BlockingHttpClient client, String username = "valid", String password = "valid") {
        def creds = new UsernamePasswordCredentials(username, password)
        def resp = client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)
        resp.body().accessToken
    }

    HttpResponse get(BlockingHttpClient client, String path, String token = null, String prefix = 'Bearer') {
        HttpRequest req = HttpRequest.GET(path)
        if (token != null) {
            req = req.header("Authorization", "${prefix} ${token}".toString())
        }
        client.exchange(req, String)
    }

    String loginWith(String username = "valid") {
        loginWith(client, username)
    }

    HttpResponse get(String path, String token = null, String prefix = 'Bearer') {
        get(client, path, token, prefix)
    }
}
