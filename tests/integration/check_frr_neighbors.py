#!/usr/bin/env python3
"""Validate every expected live FRRouting adjacency from vtysh JSON.

Do not confuse routes installed in the Linux FIB with stable peer state.
FRR 10.x reports BGP peers in ipv4Unicast.peers, and OSPF neighbors as
router-ID keyed lists containing nbrState (for example, Full/-).
"""
import json
import pathlib
import sys


def _ospf_records(data, router_id):
    """Find a named OSPF router ID in FRR's VRF or neighbor-map shape."""
    if isinstance(data, dict):
        if router_id in data:
            value = data[router_id]
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                return [value]
        if data.get("routerId") == router_id or data.get("nbrId") == router_id:
            return [data]
        for value in data.values():
            matches = _ospf_records(value, router_id)
            if matches:
                return matches
    if isinstance(data, list):
        for item in data:
            matches = _ospf_records(item, router_id)
            if matches:
                return matches
    return []


def check_neighbors(mode, data, expected):
    """Raise ValueError if ANY expected authenticated overlay neighbor is down."""
    if mode not in {"bgp", "ospf"}:
        raise ValueError(f"unsupported protocol: {mode}")
    if not isinstance(data, dict):
        raise ValueError("FRR response is not a JSON object")
    if not expected or len(set(expected)) != len(expected):
        raise ValueError("expected neighbors must be present and distinct")

    failed = []
    for address in expected:
        if mode == "bgp":
            peers = data.get("ipv4Unicast", data).get("peers", {})
            if not isinstance(peers, dict):
                raise ValueError("FRR BGP JSON missing peers object")
            peer = peers.get(address, {})
            state = peer.get("state", "absent") if isinstance(peer, dict) else "invalid"
            if state != "Established":
                failed.append(f"{address}={state}")
        else:
            records = _ospf_records(data.get("neighbors", data), address)
            states = [
                entry.get("nbrState", entry.get("state", "absent"))
                for entry in records
            ]
            if not any(
                isinstance(state, str) and state.split("/", 1)[0] == "Full"
                for state in states
            ):
                failed.append(f"{address}={states or ['absent']}")

    if failed:
        raise ValueError(f"{mode.upper()} neighbor(s) not converged: {', '.join(failed)}")
    return len(expected)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 3:
        print("usage: check_frr_neighbors.py bgp|ospf SUMMARY.json NEIGHBOR_IP...", file=sys.stderr)
        return 2
    mode, filename, *expected = args
    try:
        data = json.loads(pathlib.Path(filename).read_text(encoding="utf-8"))
        count = check_neighbors(mode, data, expected)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL {mode} live FRR adjacency check: {exc}", file=sys.stderr)
        return 1
    print(f"PASS {mode}: {count}/{count} expected live FRR neighbors Established/Full")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
