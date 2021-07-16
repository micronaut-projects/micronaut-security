package io.micronaut.security.oauth2.docs.github;

//tag::clazz[]
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Header
import io.micronaut.http.client.annotation.Client
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux

@Header(name = "User-Agent", value = "Micronaut")
@Client("https://api.github.com")
interface GithubApiClient {

    @Get("/user")
    Publisher<GithubUser> getUser(@Header("Authorization") String authorization)
}
//end::clazz[]