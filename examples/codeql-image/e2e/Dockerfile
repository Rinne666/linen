ARG BASE_IMAGE=linen-codeql:local
FROM ${BASE_IMAGE}

USER root
COPY examples/codeql-image/e2e/fixture-query-pack/ \
    /opt/codeql/qlpacks/linen/fixture-sqlite-input/0.0.1/
RUN chmod -R a+rX /opt/codeql/qlpacks/linen
USER 1000:1000
