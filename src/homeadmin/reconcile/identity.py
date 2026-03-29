"""Deterministic first-pass reconciliation for device observations."""

from __future__ import annotations

from homeadmin.models.observations import (
    Contradiction,
    DeviceObservation,
    ProvisionalIdentity,
    ReconciliationResult,
    ServiceEvidence,
)


class _Cluster:
    def __init__(self) -> None:
        self.observations: list[DeviceObservation] = []
        self.discrepancies: list[Contradiction] = []


def reconcile_observations(observations: list[DeviceObservation]) -> ReconciliationResult:
    """Merge observations into provisional identities.

    Precedence: MAC (strong) > stable hostname/service evidence > IP (cautious).
    """

    result = ReconciliationResult()
    by_mac: dict[str, _Cluster] = {}
    by_hostname: dict[str, _Cluster] = {}
    by_ip: dict[str, _Cluster] = {}

    for observation in observations:
        cluster = _select_cluster(observation, by_mac, by_hostname, by_ip)
        if cluster is None:
            cluster = _Cluster()

        _merge_with_checks(cluster, observation)
        cluster.observations.append(observation)
        _index_cluster(cluster, observation, by_mac, by_hostname, by_ip)

    seen_clusters: set[int] = set()
    all_clusters = [*by_mac.values(), *by_hostname.values(), *by_ip.values()]
    for cluster in all_clusters:
        if id(cluster) in seen_clusters:
            continue
        seen_clusters.add(id(cluster))

        identity = _materialize_identity(cluster)
        result.identities.append(identity)
        result.discrepancies.extend(cluster.discrepancies)

    return result


def _select_cluster(
    observation: DeviceObservation,
    by_mac: dict[str, _Cluster],
    by_hostname: dict[str, _Cluster],
    by_ip: dict[str, _Cluster],
) -> _Cluster | None:
    if observation.mac and observation.mac in by_mac:
        return by_mac[observation.mac]

    if observation.hostname and observation.hostname in by_hostname:
        return by_hostname[observation.hostname]

    if observation.ip and observation.ip in by_ip:
        return by_ip[observation.ip]

    return None


def _merge_with_checks(cluster: _Cluster, observation: DeviceObservation) -> None:
    existing_macs = {item.mac for item in cluster.observations if item.mac}
    if observation.mac and existing_macs and observation.mac not in existing_macs:
        cluster.discrepancies.append(
            Contradiction(
                category="mac_conflict",
                detail=(
                    f"Conflicting MACs in candidate identity: "
                    f"observed={observation.mac}, existing={sorted(existing_macs)}"
                ),
                related_observations=tuple([*cluster.observations, observation]),
            )
        )

    existing_hostnames = {item.hostname for item in cluster.observations if item.hostname}
    if observation.hostname and existing_hostnames and observation.hostname not in existing_hostnames:
        cluster.discrepancies.append(
            Contradiction(
                category="hostname_conflict",
                detail=(
                    f"Conflicting hostnames in candidate identity: "
                    f"observed={observation.hostname}, existing={sorted(existing_hostnames)}"
                ),
                related_observations=tuple([*cluster.observations, observation]),
            )
        )

    if observation.ip:
        existing_ips = {item.ip for item in cluster.observations if item.ip}
        if existing_ips and observation.ip not in existing_ips and not observation.mac:
            cluster.discrepancies.append(
                Contradiction(
                    category="ip_only_link_warning",
                    detail=(
                        f"IP-only linkage is weak: observed={observation.ip}, "
                        f"existing={sorted(existing_ips)}"
                    ),
                    related_observations=tuple([*cluster.observations, observation]),
                )
            )


def _index_cluster(
    cluster: _Cluster,
    observation: DeviceObservation,
    by_mac: dict[str, _Cluster],
    by_hostname: dict[str, _Cluster],
    by_ip: dict[str, _Cluster],
) -> None:
    if observation.mac:
        by_mac[observation.mac] = cluster
    if observation.hostname:
        by_hostname[observation.hostname] = cluster
    if observation.ip:
        by_ip[observation.ip] = cluster


def _materialize_identity(cluster: _Cluster) -> ProvisionalIdentity:
    macs = sorted({item.mac for item in cluster.observations if item.mac})
    hostnames = sorted({item.hostname for item in cluster.observations if item.hostname})
    ips = sorted({item.ip for item in cluster.observations if item.ip})

    all_services: dict[tuple[int, str, str | None, str | None], ServiceEvidence] = {}
    for observation in cluster.observations:
        for service in observation.services:
            key = (service.port, service.protocol, service.state, service.service)
            all_services[key] = service

    if macs:
        identity_key = f"mac:{macs[0]}"
    elif hostnames:
        identity_key = f"hostname:{hostnames[0]}"
    elif ips:
        identity_key = f"ip:{ips[0]}"
    else:
        identity_key = "unknown"

    return ProvisionalIdentity(
        identity_key=identity_key,
        ips=tuple(ips),
        macs=tuple(macs),
        hostnames=tuple(hostnames),
        services=tuple(sorted(all_services.values(), key=lambda item: (item.port, item.protocol))),
        observations=tuple(cluster.observations),
        discrepancies=tuple(cluster.discrepancies),
    )
