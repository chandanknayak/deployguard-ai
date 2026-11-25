"""
tests/unit/test_diff_parser.py — Unit tests for the unified diff parser.

Tests cover:
    - Basic function-level diff parsing
    - Hunk header extraction and line number computation
    - New file / deleted file / renamed file markers
    - Empty diff handling
    - Multi-file diffs
    - Diffs with only context lines (no additions)
"""

from __future__ import annotations

from deployguard.core.diff_parser import DiffParser, parse_diff


# ──────────────────────────────────────────────────────────────────────────
# Test fixtures
# ──────────────────────────────────────────────────────────────────────────


SIMPLE_DIFF = """\
diff --git a/src/payments/charge.py b/src/payments/charge.py
index a1b2c3d..e4f5a6b 100644
--- a/src/payments/charge.py
+++ b/src/payments/charge.py
@@ -45,7 +45,10 @@ class ChargeHandler:
 def __init__(self):
-    self.retry_count = 3
+    self.retry_count = 5
+    self.base_delay = 0.5
     self.timeout = 30
"""

NEW_FILE_DIFF = """\
diff --git a/src/payments/refund.py b/src/payments/refund.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/src/payments/refund.py
@@ -0,0 +1,5 @@
+def process_refund(transaction_id: str) -> bool:
+    \"\"\"Process a refund for a given transaction.\"\"\"
+    # TODO: implement
+    return True
+
"""

MULTI_FILE_DIFF = """\
diff --git a/src/auth/login.py b/src/auth/login.py
index aaa..bbb 100644
--- a/src/auth/login.py
+++ b/src/auth/login.py
@@ -10,4 +10,5 @@ def login(username: str, password: str) -> str:
     token = generate_token(username)
+    log_login_event(username)
     return token
 
diff --git a/src/payments/charge.py b/src/payments/charge.py
index ccc..ddd 100644
--- a/src/payments/charge.py
+++ b/src/payments/charge.py
@@ -20,3 +20,4 @@ def charge(amount: float) -> bool:
     gateway.charge(amount)
+    send_receipt()
     return True
"""

DELETED_FILE_DIFF = """\
diff --git a/src/legacy/old_module.py b/src/legacy/old_module.py
deleted file mode 100644
index 9876543..0000000
--- a/src/legacy/old_module.py
+++ /dev/null
@@ -1,3 +0,0 @@
-def deprecated_function():
-    pass
-
"""

RENAMED_FILE_DIFF = """\
diff --git a/src/payments/charge.py b/src/payments/charge_handler.py
similarity index 95%
rename from src/payments/charge.py
rename to src/payments/charge_handler.py
index abc..def 100644
--- a/src/payments/charge.py
+++ b/src/payments/charge_handler.py
@@ -1,3 +1,3 @@
-class Charge:
+class ChargeHandler:
     pass
"""


# ──────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────


class TestDiffParserBasic:
    """Tests for basic single-file diff parsing."""

    def test_returns_list_of_file_diffs(self) -> None:
        result = parse_diff(SIMPLE_DIFF)
        assert isinstance(result, list)
        assert len(result) == 1

    def test_correct_filename_extracted(self) -> None:
        result = parse_diff(SIMPLE_DIFF)
        assert result[0].filename == "src/payments/charge.py"

    def test_hunk_parsed(self) -> None:
        result = parse_diff(SIMPLE_DIFF)
        fd = result[0]
        assert len(fd.hunks) == 1

    def test_hunk_start_line(self) -> None:
        result = parse_diff(SIMPLE_DIFF)
        hunk = result[0].hunks[0]
        assert hunk.start_line == 45

    def test_modified_lines_non_empty(self) -> None:
        result = parse_diff(SIMPLE_DIFF)
        lines = result[0].all_modified_lines
        assert len(lines) > 0

    def test_added_lines_captured(self) -> None:
        result = parse_diff(SIMPLE_DIFF)
        lines = result[0].all_modified_lines
        # The diff adds lines at 46 and 47 (replacing line 46 and adding 47)
        assert len(lines) >= 2

    def test_total_modified_lines_positive(self) -> None:
        result = parse_diff(SIMPLE_DIFF)
        assert result[0].total_modified_lines > 0


class TestDiffParserSpecialCases:
    """Tests for new file, deleted file, and renamed file markers."""

    def test_new_file_detected(self) -> None:
        result = parse_diff(NEW_FILE_DIFF)
        assert len(result) == 1
        assert result[0].is_new_file is True

    def test_new_file_lines_captured(self) -> None:
        result = parse_diff(NEW_FILE_DIFF)
        fd = result[0]
        assert len(fd.all_modified_lines) >= 4  # 4 added lines + 1 blank

    def test_deleted_file_detected(self) -> None:
        result = parse_diff(DELETED_FILE_DIFF)
        assert len(result) == 1
        assert result[0].is_deleted_file is True

    def test_renamed_file_detected(self) -> None:
        result = parse_diff(RENAMED_FILE_DIFF)
        assert len(result) == 1
        assert result[0].is_renamed is True

    def test_renamed_file_new_name_used(self) -> None:
        result = parse_diff(RENAMED_FILE_DIFF)
        # After rename, the filename should reflect the new path
        assert "charge_handler" in result[0].filename


class TestDiffParserMultiFile:
    """Tests for multi-file diff parsing."""

    def test_two_files_returned(self) -> None:
        result = parse_diff(MULTI_FILE_DIFF)
        assert len(result) == 2

    def test_filenames_correct(self) -> None:
        result = parse_diff(MULTI_FILE_DIFF)
        filenames = {fd.filename for fd in result}
        assert "src/auth/login.py" in filenames
        assert "src/payments/charge.py" in filenames

    def test_each_file_has_hunks(self) -> None:
        result = parse_diff(MULTI_FILE_DIFF)
        for fd in result:
            assert len(fd.hunks) >= 1

    def test_auth_file_correct_line_range(self) -> None:
        result = parse_diff(MULTI_FILE_DIFF)
        auth_fd = next(fd for fd in result if "auth" in fd.filename)
        # The hunk starts at line 10
        assert auth_fd.hunks[0].start_line == 10

    def test_payments_file_correct_line_range(self) -> None:
        result = parse_diff(MULTI_FILE_DIFF)
        pay_fd = next(fd for fd in result if "payments" in fd.filename)
        assert pay_fd.hunks[0].start_line == 20


class TestDiffParserEdgeCases:
    """Tests for empty input and edge cases."""

    def test_empty_string_returns_empty_list(self) -> None:
        result = parse_diff("")
        assert result == []

    def test_whitespace_only_returns_empty_list(self) -> None:
        result = parse_diff("   \n\n  ")
        assert result == []

    def test_parser_is_reusable(self) -> None:
        parser = DiffParser()
        result1 = parser.parse(SIMPLE_DIFF)
        result2 = parser.parse(MULTI_FILE_DIFF)
        assert len(result1) == 1
        assert len(result2) == 2

    def test_file_diff_line_range_property(self) -> None:
        result = parse_diff(SIMPLE_DIFF)
        hunk = result[0].hunks[0]
        line_range = hunk.line_range
        assert line_range.start == hunk.start_line
        assert line_range.stop == hunk.end_line + 1

    def test_trailing_blank_lines_after_hunk_are_ignored(self) -> None:
        diff_with_trailing = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,1 +1,2 @@\n"
            " def ok():\n"
            "+    return 1\n"
            "\n\n\n"
        )
        result = parse_diff(diff_with_trailing)
        assert result[0].all_modified_lines == {1, 2}

