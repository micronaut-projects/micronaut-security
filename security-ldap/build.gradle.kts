plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)

    api(projects.micronautSecurity)

    testImplementation(projects.micronautSecurityJwt)

    testImplementation(mn.micronaut.http.client)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(libs.unboundid.ldapsdk)
}
