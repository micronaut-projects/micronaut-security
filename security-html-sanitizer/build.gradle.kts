plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    api(mn.micronaut.http)
    api(projects.micronautSecurity)
    api(libs.managed.owasp.java.html.sanitizer)
}

tasks.withType<Test> {
    useJUnitPlatform()
}

micronautBuild {
    binaryCompatibility {
        enabledAfter("5.1.0")
    }
}
