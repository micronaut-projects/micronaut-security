package io.micronaut.security.docs.clientcredentials;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

@Requires(property = "spec.name", value = "ClientCredentialsClientTest")
@Singleton
public class MyClass {
    private final ClientCredentialsClient googleClientCredentialsClient;

//tag::constructor[]
    public MyClass(@Named("google") ClientCredentialsClient googleClientCredentialsClient) {
        this.googleClientCredentialsClient = googleClientCredentialsClient;
    }
//end::constructor[]

    public ClientCredentialsClient getGoogleClientCredentialsClient() {
        return googleClientCredentialsClient;
    }
}
