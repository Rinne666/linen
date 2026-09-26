FROM python:3.12-slim-bookworm

# The build context must contain the extracted, platform-matching official
# CodeQL bundle in ./codeql. Keep its query packs in this immutable image so
# an audit never downloads executable analysis code.
COPY codeql/ /opt/codeql/
RUN chmod -R a+rX /opt/codeql \
    && test -x /opt/codeql/codeql

USER 1000:1000
WORKDIR /work
