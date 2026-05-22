package io.micronaut.security.oauth2.docs.github;

//tag::clazz[]
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming
import io.micronaut.core.annotation.Introspected

@Introspected
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
class GithubUser {

    String login
    String name
    String email
}
//end::clazz[]
