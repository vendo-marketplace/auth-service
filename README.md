# Auth Service

The **Auth Service** is responsible for securing the Vendo platform. It handles user authentication, authorization, token generation (JWT), Code validation, password recovery, and Google OAuth integration.

This service acts as the security backbone, providing authentication tokens that clients use to interact with other microservices in the platform.

---

# Tech Stack

* Java 17
* Spring Boot
* JWT
* Redis
* Kafka
* OpenFeign
* Google API Client
* Docker
* Eureka
* Zipkin
* Micrometer
* OpenAPI
* Swagger
* MapStruct
* Lombok
* Maven
* JUnit 5
* Mockito

---

# Architecture

The service strictly follows **Hexagonal Architecture (Ports and Adapters)** to isolate the core security and authentication logic from external frameworks, databases, and message brokers.

## Layers

**domain**
Contains the core business rules and models.

**application**
Contains the application use cases and orchestration logic.

**port**
Defines interfaces used to communicate with the outside world.

**adapter**
Implementations of external integrations.
* **adapter.in**: Entry points.
* **adapter.out**: Outgoing calls.

**infrastructure**
Framework-specific configurations and bean definitions.
* Configs for OpenAPI, Eureka, Kafka, OpenFeign, and MapStruct.

---

# Project Structure

```
src/main/java/com/vendo/auth_service
├── adapter
│   ├── auth
│   │   ├── in
│   │   └── out
│   ├── db/redis/out
│   ├── code
│   │   ├── in/messaging/kafka/producer
│   │   └── out/props
│   ├── password
│   │   ├── in/dto
│   │   └── out/mapper
│   ├── security
│   │   ├── in/config
│   │   └── out
│   ├── server/in/exception
│   ├── user
│   │   ├── in
│   │   └── out
│   └── verification
│       ├── in/dto
│       └── out/mapper
├── application
│   ├── auth
│   ├── code/common/exception
│   └── password/command
├── bootstrap
├── domain
│   ├── code
│   └── user/model
├── infrastructure
│   └── config
└── port
    ├── auth
    ├── code
    ├── security
    └── user
```

---

# Prerequisites

Before running this service, ensure the required infrastructure and core services are up.

## Dependencies

This service depends on:

- **Config Server** – provides externalized configuration
- **Service Registry (Eureka)** – for discovering `user-service`
- **Redis** – for storing temporary codes
- **Kafka** – for publishing email notification events
- **User Service** – requires synchronous communication via OpenFeign to fetch/verify user profiles

---

# Running the Service

---

## 1. Clone and run Config Server

```
git clone https://github.com/vendo-marketplace/config-server
cd config-server
mvn spring-boot:run
```


---

## 2. Clone and run Service Registry

```
git clone https://github.com/vendo-marketplace/registry-service
cd registry-service
mvn spring-boot:run
```


# Running the Service

---

## 3. Run application

Or build and run:

```
mvn clean package
java -jar target/auth-service.jar
```

---

# Environment Variables

| Variable          | Description       | Default   |
|-------------------|-------------------|-----------|
| CONFIG_SERVER_URL | Config server url | 8010      |

---

# API Documentation

Swagger UI:

```
http://localhost:8050/swagger-ui.html
```

---

# Running Tests

Run all tests

```
mvn test
```

Run integration tests

```
mvn verify
```

---

# Code Style

The project follows standard **Java code conventions**.

Key principles:

* Clean Architecture
* SOLID principles
* Immutable DTOs
* Constructor injection
* Clear separation between layers

---

# Contributing

1. Create feature branch
2. Write tests
3. Ensure tests pass
4. Create pull request

