import importlib.util
import io
import json
import os
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

_spec = importlib.util.spec_from_file_location(
    "register_runtime_release",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "register_runtime_release.py"),
)
rrr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rrr)

DIGEST = "sha256:" + "a" * 64


class FakeResp:
    def __init__(self, status):
        self.status = status

    def read(self):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Tests(unittest.TestCase):
    def run_main(self, **over):
        d = tempfile.mkdtemp()
        env = {"DIGEST": DIGEST, "VERSION": "1.2.3", "GITHUB_SHA": "f" * 40,
               "OUT": os.path.join(d, "r.json")}
        env.update(over)
        with redirect_stdout(io.StringIO()):
            code = rrr.main(env)
        return code, env["OUT"]

    def test_body_shape_single_artifact(self):
        b = rrr.build_request("1.2.3", DIGEST, "f" * 40)
        self.assertEqual(b["kind"], "platform")
        self.assertEqual(b["publisher"], "github:greenticai/greentic-start")
        self.assertEqual(b["name"], "greentic-start")
        self.assertEqual(len(b["artifacts"]), 1)
        a = b["artifacts"][0]
        self.assertEqual(a["name"], "greentic-start-distroless")
        self.assertEqual(a["digest"], DIGEST)
        self.assertEqual(a["media_type"], "application/vnd.oci.image.index.v1+json")
        self.assertEqual(a["source"], "ghcr.io/greenticai/greentic-start-distroless")
        self.assertEqual(b["provenance"]["builder"], "github-actions")
        self.assertEqual(b["rollback"], {"supported": True})
        self.assertNotIn("channel", b)

    def test_invalid_inputs_exit_2(self):
        for over in ({"DIGEST": "sha256:ABC"}, {"DIGEST": "a" * 64},
                     {"VERSION": "v1.2.3"}, {"VERSION": "1.2"}):
            with mock.patch("urllib.request.urlopen") as u:
                code, _ = self.run_main(**over)
            self.assertEqual(code, 2, over)
            u.assert_not_called()

    def test_unarmed_no_network(self):
        for over in ({}, {"ADMIN": "https://a"}, {"KEY": "k"}):
            with mock.patch("urllib.request.urlopen", side_effect=AssertionError):
                code, out = self.run_main(**over)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(out))

    def test_dry_run_no_network(self):
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError):
            code, out = self.run_main(ADMIN="https://a", KEY="k", DRY_RUN="true")
        self.assertEqual(code, 0)
        self.assertEqual(json.load(open(out))["version"], "1.2.3")

    def test_success_statuses_and_headers(self):
        for status in (200, 201):
            with mock.patch("urllib.request.urlopen", return_value=FakeResp(status)) as u:
                code, _ = self.run_main(ADMIN="https://a/", KEY="k", DRY_RUN="")
            self.assertEqual(code, 0)
            req = u.call_args[0][0]
            self.assertEqual(req.full_url, "https://a/api/v1/releases")
            h = {k.lower(): v for k, v in req.header_items()}
            self.assertEqual(h["authorization"], "Bearer k")
            self.assertEqual(h["idempotency-key"], "greentic-start-distroless-1.2.3")
            self.assertEqual(h["content-type"], "application/json")
            self.assertEqual(req.get_method(), "POST")

    def test_409_and_other_failures(self):
        for status in (409, 401, 500):
            err = urllib.error.HTTPError("u", status, "x", {}, io.BytesIO(b"no"))
            with mock.patch("urllib.request.urlopen", side_effect=err):
                code, _ = self.run_main(ADMIN="https://a", KEY="k")
            self.assertEqual(code, 1, status)
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            code, _ = self.run_main(ADMIN="https://a", KEY="k")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
