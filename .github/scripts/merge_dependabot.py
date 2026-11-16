"""Merge a verified Dependabot PR, refreshing its base and CI when necessary.

Executed from the base commit only. PR code runs in separate read-only CI jobs.
"""

import json
import os
import subprocess
import time


class MergeError(RuntimeError):
    pass


def gh(*args, token=None):
    env = os.environ.copy()
    env.pop("DEPENDABOT_UPDATE_TOKEN", None)
    if token is not None:
        env["GH_TOKEN"] = token
    return subprocess.check_output(["gh", *args], text=True, env=env).strip()


class Merger:
    def __init__(self):
        self.repo = os.environ["GH_REPO"]
        self.number = os.environ["PR_NUMBER"]
        self.url = os.environ["PR_URL"]
        self.head = os.environ["HEAD_SHA"]
        self.branch = os.environ["HEAD_REF"]
        self.pull = f"repos/{self.repo}/pulls/{self.number}"

    def check_head(self):
        pr = json.loads(gh("api", self.pull))
        if pr["state"] != "open" or pr["head"]["sha"] != self.head:
            raise MergeError("PR was closed or changed by another actor; refusing to merge")
        return pr

    def base(self):
        return gh("api", f"repos/{self.repo}/git/ref/heads/main", "--jq", ".object.sha")

    def behind(self, base):
        status = gh("api", f"repos/{self.repo}/compare/{base}...{self.head}", "--jq", ".status")
        if status not in ("ahead", "identical", "behind", "diverged"):
            raise MergeError(f"Unexpected comparison status: {status}")
        return status in ("behind", "diverged")

    def refresh(self):
        update_token = os.environ.get("DEPENDABOT_UPDATE_TOKEN", "")
        if not update_token:
            raise MergeError("Set the DEPENDABOT_UPDATE_TOKEN Actions secret to refresh "
                             "PR branches and trigger required pull_request CI")
        self.check_head()
        old = self.head
        gh("api", "--method", "PUT", self.pull + "/update-branch",
           "-f", f"expected_head_sha={old}", token=update_token)
        for _ in range(20):
            pr = json.loads(gh("api", self.pull))
            if pr["state"] != "open":
                raise MergeError("PR closed during branch update")
            if pr["head"]["sha"] != old:
                candidate = pr["head"]["sha"]
                commit = json.loads(gh("api", f"repos/{self.repo}/git/commits/{candidate}"))
                parents = commit["parents"]
                if len(parents) != 2 or parents[0]["sha"] != old:
                    raise MergeError("Unexpected head change during branch update")
                self.head = candidate
                return
            time.sleep(3)
        raise MergeError("Branch update did not complete")

    def wait_ci(self):
        for _ in range(40):
            runs = json.loads(gh("run", "list", "--workflow", "docker.yml", "--event", "pull_request",
                                 "--branch", self.branch, "--limit", "20",
                                 "--json", "databaseId,headSha"))
            run = next((r for r in runs if r["headSha"] == self.head), None)
            if run:
                gh("run", "watch", str(run["databaseId"]), "--exit-status", "--interval", "15")
                return
            time.sleep(15)
        raise MergeError("No CI run found for the expected head")

    def run(self):
        for attempt in range(3):
            self.check_head()
            base = self.base()
            if self.behind(base):
                print(f"Refreshing PR against main (attempt {attempt + 1})", flush=True)
                self.refresh()
                # A dedicated token makes this update emit pull_request CI.
                # workflow_dispatch results do not satisfy required PR checks.
            self.wait_ci()
            self.check_head()
            if self.base() != base:
                continue
            try:
                # Strict required checks provide the atomic base guard if main
                # advances after the comparison above. Never use --admin.
                gh("pr", "merge", self.url, "--squash", "--match-head-commit", self.head)
            except subprocess.CalledProcessError:
                self.check_head()
                current = self.base()
                if current != base or self.behind(current):
                    continue
                raise
            # GITHUB_TOKEN merges also need an explicit publication dispatch.
            gh("workflow", "run", "docker.yml", "--ref", "main")
            return
        raise MergeError("main kept advancing; retry limit reached without merging")


if __name__ == "__main__":
    Merger().run()
