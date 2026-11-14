"""Fail-closed tests for five-site FRRouting adjacency JSON validation."""
import json
import pathlib
import tempfile
import unittest

from check_frr_neighbors import check_neighbors, main


class FRRNeighborTests(unittest.TestCase):
    def test_bgp_all_established(self):
        peers = {
            f"10.77.0.{n}": {"state": "Established", "pfxRcd": 1}
            for n in range(2, 6)
        }
        self.assertEqual(
            check_neighbors("bgp", {"ipv4Unicast": {"peers": peers}}, list(peers)),
            4,
        )

    def test_bgp_missing_idle_and_unexpected_peers(self):
        response = {"ipv4Unicast": {"peers": {
            "10.77.0.2": {"state": "Established"},
            "10.77.0.3": {"state": "Idle", "pfxRcd": 4},
            "10.77.0.99": {"state": "Established"},
        }}}
        with self.assertRaisesRegex(ValueError, "10.77.0.3=Idle"):
            check_neighbors("bgp", response, ["10.77.0.2", "10.77.0.3"])
        with self.assertRaisesRegex(ValueError, "10.77.0.4=absent"):
            check_neighbors("bgp", response, ["10.77.0.4"])

    def test_ospf_all_full_with_frr_wrappers(self):
        peers = {
            "10.77.0.2": [{"nbrState": "Full/-", "ifaceName": "mq0"}],
            "10.77.0.3": [{"nbrState": "Full/DR", "ifaceName": "mq0"}],
            "10.77.0.4": [{"state": "Full"}],
            "10.77.0.5": [{"nbrState": "Full/Backup"}],
        }
        self.assertEqual(
            check_neighbors("ospf", {"neighbors": peers}, list(peers)), 4
        )
        self.assertEqual(
            check_neighbors("ospf", {"default": {"neighbors": peers}}, list(peers)),
            4,
        )

    def test_ospf_nonfull_and_missing_fail(self):
        with self.assertRaisesRegex(ValueError, "10.77.0.2"):
            check_neighbors("ospf", {
                "neighbors": {"10.77.0.2": [{"nbrState": "2-Way/DROther"}]}
            }, ["10.77.0.2"])
        with self.assertRaisesRegex(ValueError, "10.77.0.3"):
            check_neighbors("ospf", {
                "neighbors": {"10.77.0.2": [{"nbrState": "Full/-"}]}
            }, ["10.77.0.2", "10.77.0.3"])

    def test_rejects_empty_duplicate_and_invalid_input(self):
        with self.assertRaises(ValueError):
            check_neighbors("bgp", {}, [])
        with self.assertRaises(ValueError):
            check_neighbors("bgp", {"peers": {}}, ["10.77.0.1", "10.77.0.1"])
        with self.assertRaises(ValueError):
            check_neighbors("ospf", ["Full"], ["10.77.0.1"])
        with self.assertRaises(ValueError):
            check_neighbors("unknown", {}, ["10.77.0.1"])

    def test_cli_fails_non_json_and_idle(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = pathlib.Path(tmp) / "frr.json"
            file.write_text("% Can't open configuration file\n")
            self.assertEqual(main(["bgp", str(file), "10.77.0.2"]), 1)
            file.write_text(json.dumps({
                "ipv4Unicast": {"peers": {"10.77.0.2": {"state": "Idle"}}}
            }))
            self.assertEqual(main(["bgp", str(file), "10.77.0.2"]), 1)
            file.write_text(json.dumps({
                "ipv4Unicast": {"peers": {"10.77.0.2": {"state": "Established"}}}
            }))
            self.assertEqual(main(["bgp", str(file), "10.77.0.2"]), 0)


if __name__ == "__main__":
    unittest.main()
