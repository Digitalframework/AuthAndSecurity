# syntax=docker/dockerfile:1

# --- build -------------------------------------------------------------------
# Maven is already in this image, so the ./mvnw wrapper is not used here: it
# would only download a second copy of the same thing on every cold build.
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build

COPY pom.xml .
COPY src ./src

# The cache mount is what keeps rebuilds quick — ~/.m2 survives between builds,
# so only genuinely new dependencies are fetched, and editing a source file does
# not re-download the world. It needs BuildKit, which is the default in any
# current Docker.
#
# Tests are skipped deliberately. They run against H2 (see
# src/test/resources/application.properties) so they would work here without a
# database, but an image build is the wrong place to discover a failure — the
# host's `./mvnw test` already covers that, and skipping keeps this stage honest
# about what it is for.
RUN --mount=type=cache,target=/root/.m2 mvn -B -DskipTests package

# --- run ---------------------------------------------------------------------
FROM eclipse-temurin:25-jre
WORKDIR /app

# Nothing this application does needs root.
RUN useradd --system --create-home --uid 10001 spring

# Globbed rather than named, so a version bump in the POM does not silently
# break the build with a "file not found" three layers down.
COPY --from=build --chown=spring:spring /build/target/*.jar app.jar

USER spring
EXPOSE 8080

# Without MaxRAMPercentage the JVM sizes its heap against a fraction of the
# container limit that is far more conservative than it needs to be.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
