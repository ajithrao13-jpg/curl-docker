# Base Liquibase image
FROM liquibase/liquibase:latest

# Switch to root to copy files
USER root

# Set working directory
WORKDIR /liquibase

# Copy the JARs into the Liquibase lib directory
COPY liquibase-azure-deps-4.33.0.jar /liquibase/lib/
COPY mssql-jdbc-13.2.1.jre11.jar /liquibase/lib/

# Change ownership back to liquibase user
RUN chown -R liquibase:liquibase /liquibase/lib

# Switch back to liquibase user
USER liquibase

# Default entrypoint
ENTRYPOINT ["liquibase"]

# Show liquibase help by default
CMD ["--help"]
