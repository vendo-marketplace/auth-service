FROM maven:3.9.6-eclipse-temurin-17 AS build

WORKDIR /build

COPY pom.xml ./

RUN mvn dependency:go-offline

COPY src ./src

RUN mvn clean package -DskipTests

RUN ls -lh target

FROM eclipse-temurin:17-jdk
WORKDIR /app

COPY --from=build /build/target/auth-service*.jar auth-service.jar

EXPOSE 8050

CMD ["java", "-jar", "auth-service.jar"]
