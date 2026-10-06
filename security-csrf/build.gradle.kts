plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    api(projects.micronautSecurity)
    compileOnly(mn.micronaut.http.server)
    compileOnly(projects.micronautSecuritySession)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(projects.testSuiteUtilsSecurity)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(projects.micronautSecuritySession)
}

tasks.withType<Test> {
    useJUnitPlatform()
}
