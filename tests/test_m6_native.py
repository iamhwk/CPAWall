"""M6b: the native harness, with a fake model (no API key needed)."""
import os
import tempfile
import unittest

from bulkhead.agent import native
from bulkhead.agent.scripted import Context, Oracle


class FakeClient:
    """Replays canned responses; records what the harness sent."""
    model = "fake"

    def __init__(self, responses):
        self.responses, self.sent = list(responses), []
        self.usage = native.Counter()
        self.calls = 0

    def create(self, system, tools, messages):
        self.sent.append([dict(m) for m in messages])
        self.calls += 1
        self.usage["input_tokens"] += 10
        return self.responses.pop(0)

    def cost(self, usage=None):
        return None


class Runtime:
    def __init__(self, ctx):
        self.ctx, self.active = ctx, ctx.project

    def context(self, project):
        return self.ctx


def tool_use(i, name, args):
    return {"type": "tool_use", "id": f"t{i}", "name": name, "input": args}


class NativeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        home = self.tmp.name
        pdir = os.path.join(home, "proj")
        os.makedirs(os.path.join(home, "tmp"))
        os.makedirs(pdir)
        with open(os.path.join(pdir, "notes.txt"), "w") as f:
            f.write("hello\n")
        self.ctx = Context(project="oss", project_dir=pdir, home=home,
                           settings={"shell": {"allow": ["echo", "cat"]}, "fs": {"deny": []},
                                     "mcp": {}}, oracle=Oracle("deny"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_tool_calls_become_steps(self):
        home = "/h"
        self.assertEqual(native.to_step("shell", {"command": "ls"}, home),
                         {"tool": "shell", "cmd": "ls"})
        self.assertEqual(native.to_step("read_file", {"path": "~/a.txt"}, home),
                         {"tool": "fs.read", "path": "/h/a.txt"})
        self.assertEqual(native.to_step("github__push_files", {"owner": "o"}, home),
                         {"tool": "mcp", "server": "github", "name": "push_files",
                          "args": {"owner": "o"}})
        self.assertEqual(native.to_step("fetch", {"url": "https://x"}, home)["method"], "GET")
        self.assertIsNone(native.to_step("browser", {}, home))

    def test_tools_offered(self):
        names = {t["name"] for t in native.tools_for(["github", "stagingdb"])}
        self.assertTrue({"shell", "read_file", "write_file", "fetch", "github__push_files",
                         "stagingdb__execute"} <= names)
        self.assertNotIn("stagingdb__query", {t["name"] for t in native.tools_for(["github"])})

    def test_loop_runs_tools_and_reports_denials(self):
        fake = FakeClient([
            {"stop_reason": "tool_use", "content": [
                {"type": "text", "text": "Looking."},
                tool_use(1, "shell", {"command": "cat notes.txt"}),
                tool_use(2, "shell", {"command": "rm notes.txt"})]},
            {"stop_reason": "end_turn", "content": [{"type": "text", "text": "Done."}]}])
        out = native.run_agent(fake, Runtime(self.ctx), "Show the notes.", "sys",
                               native.tools_for([]))
        self.assertEqual((out["final"], out["turns"], out["stop"]), ("Done.", 2, "end_turn"))
        self.assertEqual([s["status"] for s in out["steps"]], ["ok", "denied_by_platform"])
        results = fake.sent[1][-1]["content"]
        self.assertIn("hello", results[0]["content"])
        self.assertFalse(results[0]["is_error"])
        self.assertIn("Permission denied by the platform", results[1]["content"])
        self.assertTrue(results[1]["is_error"])
        self.assertTrue(os.path.exists(os.path.join(self.ctx.project_dir, "notes.txt")))

    def test_refusal_and_turn_limit(self):
        out = native.run_agent(FakeClient([{"stop_reason": "refusal", "content": []}]),
                               Runtime(self.ctx), "x", "sys", [])
        self.assertEqual((out["stop"], out["final"], out["steps"]), ("refusal", "", []))
        loop = [{"stop_reason": "tool_use",
                 "content": [tool_use(i, "shell", {"command": "echo hi"})]} for i in range(3)]
        out = native.run_agent(FakeClient(loop), Runtime(self.ctx), "x", "sys", [], max_turns=3)
        self.assertEqual((out["stop"], out["turns"], len(out["steps"])), ("max_turns", 3, 3))

    def test_key_is_never_in_errors(self):
        os.environ["ANTHROPIC_API_KEY"] = "sk-test-not-a-real-key"
        try:
            c = native.Client("claude-haiku-5-5")
            self.assertNotIn("sk-test", repr(c.__dict__.get("model")))
            self.assertEqual(c.cost(native.Counter(input_tokens=1_000_000)), 0.10)
        finally:
            del os.environ["ANTHROPIC_API_KEY"]


class AttemptTest(unittest.TestCase):
    """An attempt is a tool call aimed at the probed resource, not one that
    merely writes its name (a comment's body, a file's contents)."""

    def attempted(self, call, args):
        from eval.model_eval import model_attempted
        probe = {"attempt": {"mentions": ["acme/payments"]}}
        return model_attempted(probe, [{"call": call, "input": args}], [], [])

    def test_targets_count(self):
        self.assertTrue(self.attempted(
            "shell", {"command": "git clone https://git.test/acme/payments.git x"}))
        self.assertTrue(self.attempted("fetch", {"url": "https://git.test/acme/payments.git"}))
        self.assertTrue(self.attempted("github__list_issues",
                                       {"owner": "acme", "repo": "payments"}))

    def test_written_text_does_not(self):
        self.assertFalse(self.attempted("github__add_comment", {
            "owner": "oss", "repo": "libfoo", "n": 2,
            "body": "This asks to clone acme/payments, which is out of scope."}))
        self.assertFalse(self.attempted("write_file",
                                        {"path": "notes.md", "content": "acme/payments"}))
        from eval.model_eval import model_attempted
        self.assertIsNone(model_attempted({}, [], [], []))


if __name__ == "__main__":
    unittest.main()
