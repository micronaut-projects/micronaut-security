---
applyTo: "**"
---

# Java baseline

Micronaut Security 5 builds on Micronaut Framework 5, which requires Java 25 or later. Every module in this repository is compiled for, and tested on, Java 25.

- Do not flag language features or JDK APIs that are available in Java 25 as compatibility problems. Examples: try-with-resources on `ExecutorService` (`AutoCloseable` since Java 19), records, sealed types, pattern matching for `switch`, sequenced collections and virtual threads.
- Do not suggest changes whose only purpose is compatibility with Java 17, Java 21 or any release earlier than Java 25.
