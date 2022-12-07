plugins {
    id "io.micronaut.build.internal.security-module"
}

dependencies {
    annotationProcessor(mn.micronaut.graal)
    annotationProcessor(mnSerde.micronaut.serde.processor)
    implementation(mnSerde.micronaut.serde.jackson)
    api(mn.micronaut.http)
    api(mn.micronaut.http.server)
    api project(":security")
    api(libs.managed.nimbus.jose.jwt)

    implementation(mnReactor.micronaut.reactor)
    testImplementation(libs.bcpkix.jdk15on)
    testImplementation(libs.bcprov.jdk15on)

    testImplementation(mn.micronaut.management)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation project(":test-suite-utils")
    testImplementation project(":test-suite-utils-security")
    testImplementation(mnMultitenancy.micronaut.multitenancy)
    testImplementation(mnViews.micronaut.views.velocity)
    testRuntimeOnly(libs.velocity.engine.core)
    testImplementation(mn.snakeyaml)
    testImplementation(mn.micronaut.websocket)
    testImplementation(mn.groovy.json)
}

test {
    testLogging.showStandardStreams = true
    testLogging.exceptionFormat = 'full'
}
