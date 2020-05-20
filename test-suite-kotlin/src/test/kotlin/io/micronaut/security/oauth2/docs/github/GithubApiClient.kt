package io.micronaut.security.oauth2.docs.github

//tag::clazz[]
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Header
import io.micronaut.http.client.annotation.Client
import io.reactivex.Flowable

@Header(name = "User-Agent", value = "Micronaut")
@Client("https://api.github.com")
interface GithubApiClient {

    @Get("/user")
    fun getUser(@Header("Authorization") authorization: String): Flowable<GithubUser>
}
//end::clazz[]