package io.micronaut.security.oauth2.docs.github;

//tag::clazz[]

import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.client.annotation.Client;
import org.reactivestreams.Publisher;

@Header(name = "User-Agent", value = "Micronaut")
@Client("https://api.github.com")
public interface GithubApiClient {

    @Get("/user")
    Publisher<GithubUser> getUser(@Header("Authorization") String authorization);
}
//end::clazz[]