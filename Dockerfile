# Start from the official Liquibase image
FROM liquibase/liquibase:latest

# Set working directory
WORKDIR /liquibase

USER root

# Set default user back to liquibase (good practice)
USER liquibase

# Default entrypoint (can be overridden in docker run or compose)
ENTRYPOINT ["liquibase"]

# Default command (runs when container starts without args)
CMD ["--help"]
