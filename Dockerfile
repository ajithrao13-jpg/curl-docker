FROM eclipse-temurin:17-jdk # chnages t jfrog jdk images

ARG LIQUIBASE_VERSION=5.0.1

USER root


# if apt-get not working use yum 
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ca-certificates curl unzip && \
    rm -rf /var/lib/apt/lists/* && \
    update-ca-certificates

# Download, install, and clean up in a single layer
RUN set -eux; \
    curl -L -o liquibase.tar.gz "https://github.com/liquibase/liquibase/releases/download/v${LIQUIBASE_VERSION}/liquibase-${LIQUIBASE_VERSION}.tar.gz" && \
    mkdir -p /opt/liquibase && \
    tar -xzf liquibase.tar.gz -C /opt/liquibase && \
    ln -s /opt/liquibase/liquibase /usr/local/bin/liquibase && \
    rm liquibase.tar.gz

ENV PATH="/opt/liquibase:${PATH}"

WORKDIR /workspace

CMD ["liquibase", "--version"]


