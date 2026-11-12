package io.micronaut.security.docs.clientcredentials

import io.micronaut.context.annotation.Requires
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient
import jakarta.inject.Named
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "ClientCredentialsClientTest")
@Singleton
class MyClass {
    final ClientCredentialsClient googleClientCredentialsClient

//tag::constructor[]
    MyClass(@Named("google") ClientCredentialsClient googleClientCredentialsClient) {
        this.googleClientCredentialsClient = googleClientCredentialsClient
    }
//end::constructor[]
}
