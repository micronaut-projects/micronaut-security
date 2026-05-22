plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    api(mn.micronaut.http)
    api(mn.micronaut.http.server)
    api(projects.micronautSecurity)
    api(libs.managed.jpaseto.api)
    implementation(platform(libs.managed.jackson.bom))
    implementation(libs.managed.bcprov.jdk18on)
    implementation(libs.managed.jpaseto.bouncy.castle) {
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
    }
    implementation(libs.managed.jpaseto.impl)
    implementation(libs.managed.jpaseto.jackson)
    implementation(mnReactor.micronaut.reactor)
    testAnnotationProcessor(projects.micronautSecurityProcessor)
    testCompileOnly(projects.micronautSecurityProcessor)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.testSuiteUtils)
    testImplementation(projects.testSuiteUtilsSecurity)
}
