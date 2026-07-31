# CloudBeaver runtime image — Lumnus fork.
#
# WHY THIS FILE EXISTS
# Upstream ships no Dockerfile in-tree; the published image is built out-of-band. The fork needs one
# because it carries an extra OSGi bundle (io.lumnus.dbeaver.auth.openbao) that must be inside the
# product assembly. Overlaying our jars onto the published dbeaver/cloudbeaver image is NOT an
# option: ours are compiled against 26.1.5 core while the published tag is 25.0.2, so OSGi
# resolution fails at boot.
#
# SHAPE
# Stage 1 assembles the layout `deploy/build-backend.sh` produces; stage 2 is a JRE runtime.
# The heavy compile (maven/Tycho + yarn) happens BEFORE this file — see deploy/assemble.sh — because
# the backend build needs the dbeaver and dbeaver-common repos as SIBLINGS of the cloudbeaver
# checkout, which a single docker build context cannot express. That is the two-phase-build gap
# named in docs/rules/optional/fork-build-publish.md; assemble.sh is the pre-build hook.
#
#   ../assemble.sh                                   # mvn + yarn + copy -> deploy/cloudbeaver/
#   docker build -f deploy/docker/Dockerfile -t <ref> deploy/
#
# Runs unprivileged; the workspace is the only writable path.

FROM eclipse-temurin:21-jre-noble AS runtime

LABEL org.opencontainers.image.title="CloudBeaver (Lumnus)" \
      org.opencontainers.image.description="CloudBeaver CE with the OpenBao dynamic-credentials auth model" \
      org.opencontainers.image.source="https://github.com/Lumnus/cloudbeaver" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN set -eux; \
    apt-get update; \
    # curl for the healthcheck; tini so the JVM gets signals and does not become PID 1 with no
    # reaper (the same PID-1 trap that made `kill -HUP 1` seal an OpenBao pod earlier in this arc).
    apt-get install -y --no-install-recommends curl tini; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd -r -g 10001 cloudbeaver; \
    useradd -r -u 10001 -g cloudbeaver -d /opt/cloudbeaver -s /usr/sbin/nologin cloudbeaver

WORKDIR /opt/cloudbeaver

# Produced by deploy/assemble.sh — server/, web/, conf/, drivers/, workspace/, *.sh
COPY --chown=cloudbeaver:cloudbeaver cloudbeaver/ /opt/cloudbeaver/

RUN set -eux; \
    chmod +x /opt/cloudbeaver/*.sh || true; \
    mkdir -p /opt/cloudbeaver/workspace; \
    chown -R cloudbeaver:cloudbeaver /opt/cloudbeaver

USER cloudbeaver

# 8978 is CloudBeaver's default; the chart/Service maps it.
EXPOSE 8978

# Only the workspace is mutable — conf and server stay as built, so a restart cannot silently
# inherit hand-edited runtime state (the nifi-discipline lesson: runtime config is a projection).
VOLUME ["/opt/cloudbeaver/workspace"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8978/status || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["./run-cloudbeaver-server.sh"]
