# Maven 3.9.16, Temurin JDK 26.0.2.1; release-21 bytecode. Digest pins the base.
FROM maven:3.9-eclipse-temurin-26@sha256:b2c1ad85954592f9928e84327c65201f308ad9b5d8ed7d5b823717c97bf23fbb AS build
WORKDIR /build
COPY pom.xml maven-build.sh central-fallback.xml central-fallback-eu.xml ./
COPY src src
RUN sh maven-build.sh
COPY generate-keys.sh client-cert.pem ./
RUN sh generate-keys.sh /build/test-keys && keytool -importcert -noprompt -alias fixture-client -file client-cert.pem -keystore test-keys/server.p12 -storepass fixture-only

FROM maven:3.9-eclipse-temurin-26@sha256:b2c1ad85954592f9928e84327c65201f308ad9b5d8ed7d5b823717c97bf23fbb
WORKDIR /fixture
COPY --from=build /build/target/classes ./classes
COPY --from=build /build/target/dependency ./lib
COPY --from=build /build/test-keys ./test-keys
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=50", "-cp", "classes:lib/*", "fixture.Fixture"]
