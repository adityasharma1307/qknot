# syntax=docker/dockerfile:1
#
# Stages:
#   builder  - virtualenv with qknot and its core dependencies
#   liboqs   - liboqs shared library for the test suite's `pqc-fast` extra
#   test     - runtime base plus dev extras and the test tree (CI only)
#   runtime  - default target: slim, non-root, `qknot` on PATH
#
# Both Python bases are pinned to one patch release and its digest, so every
# stage shares /usr/local/bin/python and the copied virtualenvs stay valid.
# Update the pins together, for example with Dependabot (`docker` ecosystem).
ARG PYTHON_BUILD_IMAGE=python:3.12.16-bookworm@sha256:21206b8f02efda6d737e402e1c716b650ad30605843a36e4bcb55463a7ebdf37
ARG PYTHON_RUNTIME_IMAGE=python:3.12.16-slim-bookworm@sha256:62ed8e07e544e8555c5d93748d5275015136b7f5c52b5e8679b4de339c3779d3

FROM ${PYTHON_BUILD_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

FROM ${PYTHON_BUILD_IMAGE} AS liboqs
ARG LIBOQS_VERSION=0.16.0
RUN pip install --no-cache-dir cmake ninja \
    && git clone --depth 1 --branch "${LIBOQS_VERSION}" \
        https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -G Ninja \
        -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    && cmake --build /tmp/liboqs/build \
    && cmake --install /tmp/liboqs/build \
    && rm -rf /tmp/liboqs

FROM builder AS test-builder
RUN pip install ".[dev,register,transparency,audit,pqc-fast]"

FROM ${PYTHON_RUNTIME_IMAGE} AS test
RUN groupadd --system --gid 10001 qknot \
    && useradd --system --gid qknot --uid 10001 --create-home qknot
COPY --from=liboqs /opt/liboqs/lib/ /usr/local/lib/
RUN ldconfig
COPY --from=test-builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN install -d -o qknot -g qknot /app
WORKDIR /app
COPY --chown=qknot:qknot . /app
USER qknot
CMD ["python", "-m", "pytest", "-p", "no:cacheprovider"]

FROM ${PYTHON_RUNTIME_IMAGE} AS runtime
RUN groupadd --system --gid 10001 qknot \
    && useradd --system --gid qknot --uid 10001 --create-home qknot
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER qknot
WORKDIR /home/qknot
ENTRYPOINT ["qknot"]
CMD ["--help"]
