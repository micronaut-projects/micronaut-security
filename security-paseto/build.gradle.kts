plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    api(mn.micronaut.http)
    api(mn.micronaut.http.server)
    api(projects.micronautSecurity)
    api(libs.managed.jpaseto.api)
    implementation(libs.managed.jpaseto.bouncy.castle)
    implementation(libs.managed.jpaseto.impl)
    implementation(libs.managed.jpaseto.jackson)
    implementation(mnReactor.micronaut.reactor)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.testSuiteUtils)
    testImplementation(projects.testSuiteUtilsSecurity)
}
