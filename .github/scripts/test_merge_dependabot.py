import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("merge_dependabot", Path(__file__).with_name("merge_dependabot.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GitHub:
    def __init__(self, scenario="clean"):
        self.scenario = scenario
        self.head = "head0"
        self.base = "base0" if scenario == "clean" else "base1"
        self.parent_base = "base0"
        self.calls = []
        self.validated = []
        self.updates = 0
        self.merges = 0
        self.run_queries = 0
        self.previous_head = None

    def __call__(self, *args, token=None):
        if args[:3] == ("api", "--method", "PUT"):
            if token != "dedicated-update-token":
                raise AssertionError("branch refresh must use the dedicated token")
        elif token is not None:
            raise AssertionError("dedicated token used outside branch refresh")
        self.calls.append(args)
        if args[:2] == ("api", "repos/example/repo/pulls/2"):
            return json.dumps({"state": "open", "head": {"sha": self.head}})
        if args[:2] == ("api", "repos/example/repo/git/ref/heads/main"):
            return self.base
        if args[0] == "api" and "/compare/" in args[1]:
            return "ahead" if self.parent_base == self.base else "diverged"
        if args[0] == "api" and "/git/commits/" in args[1]:
            parents = [{"sha": self.previous_head}, {"sha": self.base}]
            if self.scenario == "foreign-update":
                parents = [{"sha": "foreign"}]
            return json.dumps({"parents": parents})
        if args[:3] == ("api", "--method", "PUT"):
            if self.scenario == "conflict":
                raise subprocess.CalledProcessError(1, args)
            if args[-1] != "expected_head_sha=" + self.head:
                raise AssertionError("branch update did not match expected head")
            self.updates += 1
            self.previous_head = self.head
            self.head = f"head{self.updates}"
            self.parent_base = self.base
            return "{}"
        if args[:2] == ("workflow", "run"):
            return ""
        if args[:2] == ("run", "list"):
            event = args[args.index("--event") + 1]
            if event != "pull_request":
                raise AssertionError("watching the wrong CI event after update")
            self.run_queries += 1
            if self.scenario == "missing":
                return "[]"
            # A newer run for a different SHA must never be selected.
            return json.dumps([{"databaseId": "wrong", "headSha": "other"},
                               {"databaseId": self.head, "headSha": self.head}])
        if args[:2] == ("run", "watch"):
            if args[2] != self.head:
                raise AssertionError("CI head does not match PR head")
            if self.scenario == "ci-failure":
                raise subprocess.CalledProcessError(1, args)
            self.validated.append(self.head)
            if self.scenario == "foreign-head":
                self.head = "foreign"
            if self.scenario == "busy" or (self.scenario == "advances" and len(self.validated) == 1):
                self.base += "-next"
            return ""
        if args[:2] == ("pr", "merge"):
            if args[-1] != self.head or self.head not in self.validated:
                raise AssertionError("merging an untested or changed head")
            if self.scenario == "merge-race" and self.merges == 0:
                self.merges += 1
                self.base = "racing-base"
                raise subprocess.CalledProcessError(1, args)
            if self.parent_base != self.base:
                raise AssertionError("merging against stale main")
            self.merges += 1
            return ""
        raise AssertionError(args)


class MergeTests(unittest.TestCase):
    def run_case(self, scenario, error=None):
        github = GitHub(scenario)
        env = {"GH_REPO": "example/repo", "PR_NUMBER": "2", "PR_URL": "https://github.com/example/repo/pull/2",
               "HEAD_SHA": "head0", "HEAD_REF": "dependabot/test",
               "DEPENDABOT_UPDATE_TOKEN": "" if scenario == "missing-token" else "dedicated-update-token"}
        with patch.dict(os.environ, env), patch.object(module, "gh", github), patch.object(module.time, "sleep"):
            if error:
                with self.assertRaises(error):
                    module.Merger().run()
            else:
                module.Merger().run()
        return github

    def assert_not_published(self, github):
        self.assertFalse(any(c[:2] == ("workflow", "run") and c[-1] == "main" for c in github.calls))

    def test_clean_pr(self):
        github = self.run_case("clean")
        self.assertEqual(github.updates, 0)
        self.assertEqual(github.validated, ["head0"])
        self.assertEqual(github.calls[-1], ("workflow", "run", "docker.yml", "--ref", "main"))

    def test_stale_pr_refreshes_and_runs_ci(self):
        github = self.run_case("stale")
        self.assertEqual(github.updates, 1)
        self.assertEqual(github.validated, ["head1"])
        self.assertFalse(any(c[:2] == ("workflow", "run") and c[-1] != "main" for c in github.calls))
        self.assertEqual(github.merges, 1)

    def test_missing_token_stops_before_update(self):
        github = self.run_case("missing-token", module.MergeError)
        self.assertEqual(github.updates, 0)
        self.assertEqual(github.validated, [])
        self.assertEqual(github.merges, 0)
        self.assert_not_published(github)

    def test_update_token_is_not_in_command_or_normal_credentials(self):
        with patch.dict(os.environ, {"GH_TOKEN": "normal-token", "DEPENDABOT_UPDATE_TOKEN": "dedicated-update-token"}):
            with patch.object(module.subprocess, "check_output", return_value="ok") as call:
                module.gh("api", "repos/example/repo")
                args, kwargs = call.call_args
                self.assertEqual(kwargs["env"]["GH_TOKEN"], "normal-token")
                self.assertNotIn("DEPENDABOT_UPDATE_TOKEN", kwargs["env"])
                module.gh("api", "--method", "PUT", "repos/example/repo/pulls/2/update-branch", token="dedicated-update-token")
                args, kwargs = call.call_args
                self.assertEqual(kwargs["env"]["GH_TOKEN"], "dedicated-update-token")
                self.assertNotIn("dedicated-update-token", args[0])

    def test_main_advances_during_ci(self):
        github = self.run_case("advances")
        self.assertEqual(github.updates, 2)
        self.assertEqual(github.validated, ["head1", "head2"])
        self.assertEqual(github.merges, 1)

    def test_atomic_protection_race_retries(self):
        github = self.run_case("merge-race")
        self.assertEqual(github.updates, 2)
        self.assertEqual(github.validated, ["head1", "head2"])
        self.assertEqual(github.merges, 2)

    def test_ci_failure_does_not_merge(self):
        github = self.run_case("ci-failure", subprocess.CalledProcessError)
        self.assertEqual(github.merges, 0)
        self.assert_not_published(github)

    def test_merge_conflict_stops(self):
        github = self.run_case("conflict", subprocess.CalledProcessError)
        self.assertEqual(github.merges, 0)
        self.assert_not_published(github)

    def test_foreign_head_stops(self):
        github = self.run_case("foreign-head", module.MergeError)
        self.assertEqual(github.merges, 0)
        self.assert_not_published(github)

    def test_main_keeps_moving(self):
        github = self.run_case("busy", module.MergeError)
        self.assertEqual(github.updates, 3)
        self.assertEqual(github.merges, 0)
        self.assert_not_published(github)

    def test_foreign_change_during_update_stops(self):
        github = self.run_case("foreign-update", module.MergeError)
        self.assertEqual(github.validated, [])
        self.assertEqual(github.merges, 0)
        self.assert_not_published(github)

    def test_missing_ci_stops(self):
        github = self.run_case("missing", module.MergeError)
        self.assertEqual(github.run_queries, 40)
        self.assertEqual(github.merges, 0)
        self.assert_not_published(github)


if __name__ == "__main__":
    unittest.main()
