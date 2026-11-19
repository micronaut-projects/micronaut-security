package io.micronaut.security.utils;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Java4Shell (CVE-2026-114938): every JDK Base64 decode in main sources must go through {@link Base64Utils},
 * which rejects the payloads that reach the vulnerable intrinsic. The call site tests cannot tell the guard
 * from the JDK decoder on an unaffected JDK, so this test fails instead when a call site bypasses the guard.
 */
class Base64DecoderUsageTest {

    private static final Pattern JDK_DECODER = Pattern.compile("\\bget(Url|Mime)?Decoder\\s*\\(");
    private static final List<String> SOURCE_ROOTS = List.of("java", "kotlin", "groovy");
    private static final String ALLOWED = "Base64Utils.java";

    @Test
    void mainSourcesDecodeBase64OnlyThroughBase64Utils() {
        List<Path> sources = mainSources(repositoryRoot());
        assertFalse(sources.isEmpty(), "no main sources found");
        assertTrue(sources.stream().anyMatch(p -> p.endsWith(Path.of("io", "micronaut", "security", "utils", ALLOWED))),
                "Base64Utils.java not found: the scan does not cover the security module");

        List<String> offenders = sources.stream()
                .filter(p -> !p.getFileName().toString().equals(ALLOWED))
                .filter(Base64DecoderUsageTest::usesJdkDecoder)
                .map(Path::toString)
                .toList();

        assertEquals(List.of(), offenders, "Use Base64Utils.decode or Base64Utils.decodeUrl instead of the JDK Base64 decoders");
    }

    @Test
    void patternMatchesTheJdkDecoders() {
        assertTrue(JDK_DECODER.matcher("Base64.getDecoder().decode(s)").find());
        assertTrue(JDK_DECODER.matcher("java.util.Base64.getUrlDecoder().decode(s)").find());
        assertTrue(JDK_DECODER.matcher("getMimeDecoder ()").find());
        assertFalse(JDK_DECODER.matcher("Base64.getEncoder().encodeToString(b)").find());
        assertFalse(JDK_DECODER.matcher("Base64Utils.decodeUrl(s)").find());
    }

    private static boolean usesJdkDecoder(Path source) {
        try {
            return JDK_DECODER.matcher(Files.readString(source)).find();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static List<Path> mainSources(Path root) {
        try (Stream<Path> modules = Files.list(root)) {
            return modules
                    .flatMap(module -> SOURCE_ROOTS.stream().map(lang -> module.resolve(Path.of("src", "main", lang))))
                    .filter(Files::isDirectory)
                    .flatMap(Base64DecoderUsageTest::walk)
                    .filter(p -> p.toString().endsWith(".java") || p.toString().endsWith(".kt") || p.toString().endsWith(".groovy"))
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Stream<Path> walk(Path dir) {
        try (Stream<Path> files = Files.walk(dir)) {
            return files.filter(Files::isRegularFile).toList().stream();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Path repositoryRoot() {
        Path dir = Path.of("").toAbsolutePath();
        while (dir != null) {
            if (Files.exists(dir.resolve("settings.gradle")) || Files.exists(dir.resolve("settings.gradle.kts"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("Repository root with a Gradle settings file not found");
    }
}
