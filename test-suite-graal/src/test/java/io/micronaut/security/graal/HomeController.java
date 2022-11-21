package io.micronaut.security.graal;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.json.JsonObjectSerializer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.ServerAuthentication;
import io.micronaut.security.rules.SecurityRule;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Controller
public class HomeController {

    private JsonObjectSerializer jsonObjectSerializer;

    public HomeController(JsonObjectSerializer jsonObjectSerializer) {
        this.jsonObjectSerializer = jsonObjectSerializer;
    }

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Produces(MediaType.TEXT_PLAIN)
    @Get("/serialize")
    String serialize() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("testKey", "testValue");

        ServerAuthentication auth = new ServerAuthentication("testName", null, attributes);

        Optional<byte[]> resultOpt = jsonObjectSerializer.serialize(auth);

        return new String(resultOpt.get());
    }
}
