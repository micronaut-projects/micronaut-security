plugins {
    id("java-library")
    id("io.micronaut.build.internal.security-tests")
    `java-library`
}

dependencies {
    annotationProcessor(mn.micronaut.inject.java)
    implementation(mnTest.micronaut.test.junit5)
    implementation(libs.managed.jjwt.api)
    runtimeOnly(libs.managed.jjwt.impl)
    runtimeOnly(libs.managed.jjwt.jackson)
    implementation(mnReactor.micronaut.reactor)
    implementation(projects.micronautSecurityJwt)
}
tasks.withType<Test> {
    useJUnitPlatform()
}