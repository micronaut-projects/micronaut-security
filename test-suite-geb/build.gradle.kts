plugins {
    id("io.micronaut.build.internal.security-tests")
    groovy
    `java-library`
}

repositories {
    mavenCentral()
    maven {
        setUrl("https://s01.oss.sonatype.org/content/repositories/snapshots/")
    }
}

dependencies {
    testImplementation(mn.snakeyaml)
    testImplementation(mn.reactor)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(project(":test-suite-keycloak"))
    testImplementation(project(":test-suite-utils"))
    testImplementation(project(":test-suite-utils-security"))
    testImplementation(project(":security-oauth2"))
    testImplementation(project(":security-jwt"))
    testImplementation(project(":security-session"))
    // Geb currently requires Groovy 3, and Spock for Groovy 3
    testImplementation(libs.geb.spock)
    testImplementation(libs.spock.geb)
    testImplementation(libs.geb.groovy.test)
    testImplementation(libs.testcontainers.selenium)
    testImplementation(libs.selenium.remote.driver)
    testImplementation(libs.selenium.api)
    testImplementation(libs.selenium.support)
    testRuntimeOnly(libs.selenium.firefox.driver)
    testRuntimeOnly(libs.logback.classic)
}

configurations {
    testRuntimeClasspath {
        exclude(group = "org.apache.groovy")
        this.resolutionStrategy {
            force("org.spockframework:spock-core:${libs.versions.geb.spock.get()}")
        }
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
