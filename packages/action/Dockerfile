FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
        libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 libffi8 shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Pin Syft in the image so CI PDF + SBOM generation is deterministic.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin v1.18.1

WORKDIR /src
COPY packages/shared /src/packages/shared
COPY packages/cli /src/packages/cli
RUN pip install --no-cache-dir /src/packages/shared /src/packages/cli[pdf]

WORKDIR /workspace
ENTRYPOINT ["opencra"]
CMD ["scan", "."]
