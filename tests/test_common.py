import io, re, sys, time, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))
import _cfi_common as c


class TestCompileGlob(unittest.TestCase):
    def test_double_star_matches_zero_leading_dirs(self):
        self.assertTrue(c.matches_any("migrations/0001.py", ["**/migrations/**"]))

    def test_double_star_matches_nested_leading_dirs(self):
        self.assertTrue(c.matches_any("app/db/migrations/0001.py", ["**/migrations/**"]))

    def test_single_star_does_not_cross_separator(self):
        self.assertFalse(c.matches_any("src/app/page.tsx", ["*.tsx"]))
        self.assertTrue(c.matches_any("page.tsx", ["*.tsx"]))

    def test_root_config_glob(self):
        self.assertTrue(c.matches_any("next.config.mjs", ["*.config.*"]))
        self.assertFalse(c.matches_any("src/next.config.mjs", ["*.config.*"]))

    def test_prefix_glob_matches_nested(self):
        self.assertTrue(c.matches_any("src/a/b/c.ts", ["src/**"]))


class TestCharacterClass(unittest.TestCase):
    def test_digit_class_matches_numeric_migration(self):
        self.assertTrue(c.matches_any("migrations/0001_init.py", ["**/migrations/[0-9]*"]))

    def test_digit_class_rejects_non_numeric_file(self):
        self.assertFalse(c.matches_any("migrations/runner.ts", ["**/migrations/[0-9]*"]))

    def test_negated_class_excludes_listed_chars(self):
        self.assertTrue(c.matches_any("migrations/a.py", ["**/migrations/[!0-9]*"]))
        self.assertFalse(c.matches_any("migrations/0.py", ["**/migrations/[!0-9]*"]))

    def test_unterminated_bracket_is_literal_and_does_not_raise(self):
        try:
            result = c.matches_any("a[b", ["a[b"])
        except re.error:
            self.fail("compile_glob raised re.error on an unterminated '['")
        self.assertTrue(result)

    def test_invalid_character_range_does_not_raise(self):
        # A backwards range like [9-0] or [z-a] is valid glob-class SYNTAX
        # (a well-formed [...]) but not a valid regex range once translated,
        # so re.compile() raises re.error/re.PatternError while COMPILING
        # the pattern -- before .match() is ever called, and well before
        # _find_class_end's "unterminated bracket" fallback would ever kick
        # in. This is config.json-controlled input (migrations.protected_paths,
        # architecture.allowed_paths), same trust boundary as the rest of
        # this module: it must fail open (never match), never raise.
        for bad in ["**/migrations/[9-0]*", "**/migrations/[z-a]*"]:
            try:
                result = c.matches_any("migrations/0001_init.py", [bad])
            except re.error:
                self.fail(f"compile_glob raised re.error on {bad!r}")
            self.assertFalse(result, bad)


class TestGlobReDoS(unittest.TestCase):
    """CRITICAL-2 (fix round 1): repeated '**/' must not backtrack catastrophically.

    `(?:[^/]+/)*` emitted once per '**/' token concatenates into nested,
    overlapping quantifiers when the pattern repeats the token, which blows
    up exponentially on a non-matching path. A fixed implementation collapses
    the repeated token before translating, so this must stay well under a
    generous ceiling even though an unpatched version does not finish in
    under two minutes for the same input.
    """

    def test_repeated_doublestar_slash_does_not_backtrack_catastrophically(self):
        pattern = "**/" * 40 + "nomatch_never"
        rel_path = "a/" * 40 + "nomatch"
        start = time.monotonic()
        result = c.matches_any(rel_path, [pattern])
        elapsed = time.monotonic() - start
        self.assertFalse(result)
        self.assertLess(elapsed, 2.0, f"compile_glob took {elapsed:.2f}s -- ReDoS regression")

    def test_repeated_bare_doublestar_does_not_backtrack_catastrophically(self):
        pattern = "**" * 40 + "nomatch_never"
        rel_path = "a" * 80 + "nomatch"
        start = time.monotonic()
        result = c.matches_any(rel_path, [pattern])
        elapsed = time.monotonic() - start
        self.assertFalse(result)
        self.assertLess(elapsed, 2.0, f"compile_glob took {elapsed:.2f}s -- ReDoS regression")

    def test_repeated_star_does_not_backtrack_catastrophically(self):
        pattern = "*" * 60 + "nomatch_never"
        rel_path = "a" * 80 + "nomatch"
        start = time.monotonic()
        result = c.matches_any(rel_path, [pattern])
        elapsed = time.monotonic() - start
        self.assertFalse(result)
        self.assertLess(elapsed, 2.0, f"compile_glob took {elapsed:.2f}s -- ReDoS regression")

    def test_collapsed_doublestar_slash_still_matches_correctly(self):
        # Collapsing repeated '**/' must not change matching semantics.
        self.assertTrue(c.matches_any("app/db/migrations/0001.py",
                                       ["**/**/migrations/**"]))
        self.assertFalse(c.matches_any("app/db/migrations", ["**/**/x/**"]))


class TestReadEventDefensiveParsing(unittest.TestCase):
    """CRITICAL-1 (fix round 1): a pathologically nested JSON payload must
    fail open (return None), not crash the hook with RecursionError."""

    def test_deeply_nested_stdin_fails_open(self):
        payload = "[" * 60000 + "]" * 60000
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(payload)
        try:
            start = time.monotonic()
            result = c.read_event()
            elapsed = time.monotonic() - start
        finally:
            sys.stdin = old_stdin
        self.assertIsNone(result)
        self.assertLess(elapsed, 5.0)

    def test_deeply_nested_config_fails_open(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / ".claude-for-idiots"
            cfg_dir.mkdir()
            payload = "[" * 60000 + "]" * 60000
            (cfg_dir / "config.json").write_text(payload)
            start = time.monotonic()
            result = c.load_config(tmp)
            elapsed = time.monotonic() - start
        self.assertIsNone(result)
        self.assertLess(elapsed, 5.0)


class TestRelativize(unittest.TestCase):
    def test_dot_dot_returns_none(self):
        self.assertIsNone(c.relativize("..", "/proj"))

    def test_traversal_back_to_project_root_returns_none(self):
        self.assertIsNone(c.relativize("sub/../..", "/proj"))

    def test_strips_dot_segments(self):
        self.assertEqual(c.relativize("./alembic/./versions/a.py", "/proj"),
                         "alembic/versions/a.py")

    def test_absolute_inside_project(self):
        self.assertEqual(c.relativize("/proj/src/x.ts", "/proj"), "src/x.ts")

    def test_outside_project_returns_none(self):
        self.assertIsNone(c.relativize("/etc/passwd", "/proj"))
        self.assertIsNone(c.relativize("../../etc/passwd", "/proj"))

    def test_non_ascii_path_is_ordinary(self):
        self.assertEqual(c.relativize("/proj/src/configuração.py", "/proj"),
                         "src/configuração.py")
        self.assertTrue(c.matches_any("src/configuração.py", ["src/**"]))

    def test_windows_style_separators_are_normalized(self):
        self.assertEqual(c.relativize("src\\app\\page.tsx", "/proj"), "src/app/page.tsx")

    def test_empty_path_returns_none(self):
        self.assertIsNone(c.relativize("", "/proj"))


class TestConfigHelpers(unittest.TestCase):
    def test_section_rejects_non_mapping(self):
        self.assertEqual(c.section({"architecture": "layered"}, "architecture"), {})
        self.assertEqual(c.section({"architecture": ["a"]}, "architecture"), {})
        self.assertEqual(c.section({}, "architecture"), {})

    def test_str_list_wraps_bare_string(self):
        self.assertEqual(c.str_list("src/**"), ["src/**"])
        self.assertEqual(c.str_list(["a", 2, None, "b"]), ["a", "b"])
        self.assertEqual(c.str_list(None), [])


class TestTargetPath(unittest.TestCase):
    def test_reads_file_path(self):
        self.assertEqual(c.target_path({"file_path": "a.py"}), "a.py")

    def test_falls_back_to_notebook_path(self):
        self.assertEqual(c.target_path({"notebook_path": "a.ipynb"}), "a.ipynb")

    def test_missing_returns_empty(self):
        self.assertEqual(c.target_path({}), "")
        self.assertEqual(c.target_path(None), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
