package io.micronaut.security.oauth2.docs.github

//tag::clazz[]
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.databind.PropertyNamingStrategy
import com.fasterxml.jackson.databind.annotation.JsonNaming
import io.micronaut.core.annotation.Introspected

@Introspected
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy::class)
class GithubUser {

    lateinit var login: String
    var name: String? = null
    var email: String? = null
}
//end::clazz[]
