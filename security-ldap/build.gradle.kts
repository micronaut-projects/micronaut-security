plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)
    api(project(":security"))
    implementation(libs.reactor.core)
    testImplementation(libs.reactor.test)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(libs.unboundid.ldapsdk)
}
