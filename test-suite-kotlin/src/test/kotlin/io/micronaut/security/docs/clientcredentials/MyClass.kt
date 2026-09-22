package io.micronaut.security.docs.clientcredentials

import io.micronaut.context.annotation.Requires
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient
import jakarta.inject.Named
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "ClientCredentialsClientTest")
@Singleton
//tag::constructor[]
class MyClass(@Named("google") val googleClientCredentialsClient: ClientCredentialsClient)
//end::constructor[]
