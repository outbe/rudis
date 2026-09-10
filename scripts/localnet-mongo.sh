#!/usr/bin/env bash
# Bring up (or tear down) a single-node MongoDB replica set in Docker for the
# localnet projection sink.
#
# Select this endpoint in each offchain-storage.toml [mongodb] section for a
# TRANSACTION-CAPABLE deployment (replica set or sharded cluster) - a standalone
# mongod cannot run the multi-document transactions the projection sink uses. A
# one-member `rs0` replica set is the smallest such deployment, so that is what
# we start here.
#
# Idempotent: `start` reuses an already-running instance (so localnet-restart is
# instant and does not churn the projection data).
#
# Usage: localnet-mongo.sh {start|stop|clean}
#   start  create/start the replica set, wait for a writable primary, print URI
#   stop   stop the container but keep the data volume
#   clean  stop + remove the container and its data volume
#
# Overridable via env (defaults chosen to match mise.toml's URI):
#   OUTBE_LOCALNET_MONGO_NAME   container name       (default outbe-localnet-mongodb)
#   OUTBE_LOCALNET_MONGO_PORT   host/replica port    (default 27017)
#   OUTBE_LOCALNET_MONGO_VOLUME data volume name     (default <name>-data)
set -euo pipefail

ACTION=${1:-start}
MONGO_NAME=${OUTBE_LOCALNET_MONGO_NAME:-outbe-localnet-mongodb}
MONGO_PORT=${OUTBE_LOCALNET_MONGO_PORT:-27017}
MONGO_VOLUME=${OUTBE_LOCALNET_MONGO_VOLUME:-${MONGO_NAME}-data}
MONGO_URI="mongodb://127.0.0.1:${MONGO_PORT}/?replicaSet=rs0&directConnection=true"

docker_cmd() {
  if docker info >/dev/null 2>&1; then docker "$@"; else sudo docker "$@"; fi
}

mongosh_eval() {
  docker_cmd exec "$MONGO_NAME" mongosh --quiet --port "$MONGO_PORT" --eval "$1"
}

wait_for() {
  # wait_for <what> <eval-that-exits-nonzero-until-ready>
  for _ in $(seq 1 80); do
    if mongosh_eval "$2" >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  echo "MongoDB $1 did not become ready" >&2
  return 1
}

start() {
  command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

  if ! docker_cmd inspect "$MONGO_NAME" >/dev/null 2>&1; then
    docker_cmd volume create "$MONGO_VOLUME" >/dev/null
    # Publish to the host loopback rather than `--network host`: on Docker Desktop
    # for Mac, host networking joins the Linux VM's netns, so a macOS host process
    # (the node) cannot reach 127.0.0.1:PORT - it gets connection-refused. A
    # published port works on both macOS and Linux. `directConnection=true` in the
    # URI makes the driver ignore the replica-set member's advertised address, so
    # talking to the forwarded port is fine. --bind_ip_all lets Docker's port
    # forwarder reach mongod inside the container (loopback-only bind would not).
    docker_cmd run -d --name "$MONGO_NAME" \
      -p "127.0.0.1:${MONGO_PORT}:${MONGO_PORT}" \
      --mount "source=${MONGO_VOLUME},target=/data/db" mongo:7.0 \
      --replSet rs0 --bind_ip_all --port "$MONGO_PORT" >/dev/null
  elif [ "$(docker_cmd inspect -f '{{.State.Running}}' "$MONGO_NAME")" != "true" ]; then
    docker_cmd start "$MONGO_NAME" >/dev/null
  fi

  wait_for "server" 'db.runCommand({ping:1}).ok'

  # Initiate the replica set only if it has never been initialized (survives a
  # container restart, where the config is already persisted on the volume).
  mongosh_eval "
    try { rs.status(); }
    catch (e) {
      if (e.codeName === 'NotYetInitialized')
        rs.initiate({_id:'rs0',members:[{_id:0,host:'127.0.0.1:${MONGO_PORT}'}]});
      else throw e;
    }" >/dev/null

  wait_for "primary" 'if (!db.hello().isWritablePrimary) quit(1)'

  # Prove multi-document transactions actually work before handing the URI back -
  # a mis-provisioned standalone would pass the primary check but fail here.
  mongosh_eval '
    const s = db.getMongo().startSession();
    s.startTransaction();
    s.getDatabase("outbe_localnet_txn_probe").probe.insertOne({ready:true});
    s.abortTransaction();
    s.endSession();' >/dev/null

  echo "MongoDB replica set ready: $MONGO_URI"
}

case "$ACTION" in
  start) start ;;
  stop)  docker_cmd stop "$MONGO_NAME" >/dev/null 2>&1 || true ;;
  clean)
    docker_cmd rm -f "$MONGO_NAME" >/dev/null 2>&1 || true
    docker_cmd volume rm -f "$MONGO_VOLUME" >/dev/null 2>&1 || true
    ;;
  *) echo "usage: $0 {start|stop|clean}" >&2; exit 2 ;;
esac
