plugins {
    id("io.micronaut.build.internal.security-module")
}

tasks.findBaseline.get().enabled = false

dependencies {
    annotationProcessor(mn.micronaut.graal)
    api(projects.micronautSecurity)
    implementation(mnData.micronaut.data.runtime)

    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mnReactor.micronaut.reactor)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(projects.micronautSecurityAnnotations)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mn.micronaut.http.server.netty)

    testCompileOnly(mnData.micronaut.data.processor)
    testImplementation(mnData.micronaut.data.jdbc)
    testImplementation(mnSql.h2)
    testImplementation(mnSql.micronaut.jdbc.hikari)
}
