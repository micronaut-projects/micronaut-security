package io.micronaut.security.oauth2.docs.github;

//tag::clazz[]
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;

@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class GithubUser {

    private String login;
    private String name;
    private String email;

    // getters and setters ...
    //end::clazz[]
    public String getLogin() {
        return login;
    }
    public void setLogin(String login) {
        this.login = login;
    }

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    //tag::clazz[]
}
//end::clazz[]