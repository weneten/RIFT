ARG RIFT_IMAGE=rift:bridge-test
FROM ${RIFT_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY echo.py /usr/local/libexec/rift-echo.py
COPY agent-entrypoint.sh /usr/local/sbin/rift-agent-entrypoint
ENTRYPOINT ["/usr/local/sbin/rift-agent-entrypoint"]
