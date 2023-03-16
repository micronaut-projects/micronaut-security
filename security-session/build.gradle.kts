plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)
    api(mn.micronaut.http)
    api(mnSession.micronaut.session)
    api(projects.micronautSecurity)
    api(mn.micronaut.http.server)
    implementation(mn.reactor)
    testImplementation(libs.testcontainers.selenium)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.inject.groovy)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.testSuiteUtils)
    testImplementation(projects.testSuiteUtilsSecurity)
}
