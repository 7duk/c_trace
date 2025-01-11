FROM gcc:latest

# Combine all apt commands into a single RUN and clean up in the same layer
RUN apt-get update --allow-unauthenticated --allow-insecure-repositories \
    && apt-get install -y --no-install-recommends \
        libmagic-dev \
        evince \
        wine \
        default-jre \
        python3 \
        nodejs \
        libreoffice \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/archives/*

WORKDIR /app
COPY file /app/file
COPY sandbox_v7 /app/sandbox_v7
RUN chmod +x /app/sandbox_v7

ENTRYPOINT ["./sandbox_v7"]