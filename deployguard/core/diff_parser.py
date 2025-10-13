"""
core/diff_parser.py — Unified Git Diff Parser.

Converts the raw text output of ``git diff`` (or the GitHub API's unified
diff endpoint) into a structured mapping of ``{filename → [ModifiedHunk]}``.

--- Unified Diff Format Primer ---

A unified diff file looks like this:

    diff --git a/src/payments/charge.py b/src/payments/charge.py
    index a1b2c3d..e4f5a6b 100644
    --- a/src/payments/charge.py
    +++ b/src/payments/charge.py
    @@ -45,7 +45,10 @@ class ChargeHandler:
     def __init__(self):
    -    self.retry_count = 3
    +    self.retry_count = 5
    +    self.base_delay = 0.5

The ``@@`` hunk header ``@@ -<old_start>,<old_count> +<new_start>,<new_count> @@``
tells us where in the *new* file the changed lines appear.

This module:
    1. Parses each ``diff --git`` block to extract the new filename.
    2. Parses each ``@@`` hunk header to extract ``(new_start, new_count)``.
    3. Records every line number in the new file that was **added** (``+``
       prefix) or **context** (space prefix) within a hunk window.
    4. Returns a ``{filename → list[ModifiedHunk]}`` dict for consumption by
       the AST analyzer.

Design note — "why context lines?":
    Context lines (unchanged lines shown for readability around the diff) are
    included in the line-number set because the AST analyzer uses line ranges
    to intersect *entire symbol bodies*.  A function that *contains* a changed
    line must be flagged even if the change is deep inside it — context lines
    ensure the hunk range spans the full edit window.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Final

from deployguard.exceptions import DiffParseError
from deployguard.models.analysis import ModifiedHunk

logger = logging.getLogger(__name__)

# Regex for the "diff --git" file header line
_DIFF_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^diff --git a/(?P<old_path>.+?) b/(?P<new_path>.+)$"
)

# Regex for the "@@ -<old> +<new> @@" hunk header
# Groups: old_start, old_count (optional), new_start, new_count (optional)
_HUNK_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)

# Prefix characters in diff output
_ADDED_PREFIX: Final[str] = "+"
_REMOVED_PREFIX: Final[str] = "-"
_CONTEXT_PREFIX: Final[str] = " "
_NO_NEWLINE_MARKER: Final[str] = "\\ No newline at end of file"


@dataclass
class FileDiff:
    """
    Parsed diff information for a single file.

    Attributes:
        filename: Repo-relative path to the *new* version of the file.
        old_filename: Repo-relative path to the *old* version (differs on renames).
        hunks: Ordered list of modified line ranges in the new file.
        is_new_file: ``True`` if this is a newly created file (``/dev/null`` as old).
        is_deleted_file: ``True`` if this file was deleted (``/dev/null`` as new).
        is_renamed: ``True`` if the file was renamed / moved.
    """

    filename: str
    old_filename: str
    hunks: list[ModifiedHunk] = field(default_factory=list)
    is_new_file: bool = False
    is_deleted_file: bool = False
    is_renamed: bool = False

    @property
    def all_modified_lines(self) -> set[int]:
        """
        Return the union of all modified line numbers across all hunks.

        This is the primary interface used by the AST analyzer.
        """
        lines: set[int] = set()
        for hunk in self.hunks:
            lines.update(hunk.line_range)
        return lines

    @property
    def total_modified_lines(self) -> int:
        """Total count of modified lines across all hunks."""
        return sum(h.line_count for h in self.hunks)


class DiffParser:
    """
    Stateless unified diff parser.

    Usage::

        parser = DiffParser()
        file_diffs = parser.parse(raw_diff_string)
        for fd in file_diffs:
            print(fd.filename, fd.all_modified_lines)

    The parser is designed to be instantiated once and reused across many
    calls (e.g. per-request in a web server context).
    """

    def parse(self, raw_diff: str) -> list[FileDiff]:
        """
        Parse a complete unified diff string into a list of ``FileDiff`` objects.

        Args:
            raw_diff:
                The full text of a unified diff as returned by ``git diff``
                or GitHub's ``application/vnd.github.v3.diff`` response.
                May be an empty string for PRs with no textual changes
                (e.g. pure binary file additions).

        Returns:
            A list of ``FileDiff`` instances, one per changed file.
            Returns an empty list if ``raw_diff`` is empty or contains only
            binary file entries.

        Raises:
            DiffParseError:
                If the diff is fundamentally malformed in a way that prevents
                reliable parsing (e.g. truncated mid-hunk).
        """
        if not raw_diff or not raw_diff.strip():
            logger.debug("Empty diff string received — returning empty result.")
            return []

        lines = raw_diff.splitlines()
        file_diffs: list[FileDiff] = []
        current_file: FileDiff | None = None
        current_hunk_lines: list[int] = []
        current_hunk_start: int = 0
        line_cursor: int = 0  # current line number in the *new* file within a hunk

        i = 0
        try:
            while i < len(lines):
                line = lines[i]

                # -------------------------------------------------------
                # New file block: "diff --git a/... b/..."
                # -------------------------------------------------------
                if line.startswith("diff --git "):
                    # Finalise any in-progress hunk for the previous file
                    if current_file is not None and current_hunk_lines:
                        current_file.hunks.append(
                            self._build_hunk(current_hunk_start, current_hunk_lines)
                        )
                        current_hunk_lines = []

                    current_file = self._parse_diff_header(line)
                    file_diffs.append(current_file)
                    i += 1
                    continue

                # -------------------------------------------------------
                # Special file markers: new file, deleted file, rename
                # -------------------------------------------------------
                if line.startswith("new file mode"):
                    if current_file:
                        current_file.is_new_file = True
                    i += 1
                    continue

                if line.startswith("deleted file mode"):
                    if current_file:
                        current_file.is_deleted_file = True
                    i += 1
                    continue

                if line.startswith("rename from ") or line.startswith("rename to "):
                    if current_file:
                        current_file.is_renamed = True
                    i += 1
                    continue

                # -------------------------------------------------------
                # --- / +++ file path lines (may update filename on renames)
                # -------------------------------------------------------
                if line.startswith("--- "):
                    old_path = line[4:].strip()
                    if old_path == "/dev/null" and current_file:
                        current_file.is_new_file = True
                    i += 1
                    continue

                if line.startswith("+++ "):
                    new_path = line[4:].strip()
                    if new_path == "/dev/null" and current_file:
                        current_file.is_deleted_file = True
                    elif current_file and new_path.startswith("b/"):
                        # Update filename in case of rename (b/ prefix is git convention)
                        current_file.filename = new_path[2:]
                    i += 1
                    continue

                # -------------------------------------------------------
                # Hunk header: "@@ -old +new @@"
                # -------------------------------------------------------
                if line.startswith("@@"):
                    # Save any previous hunk
                    if current_file and current_hunk_lines:
                        current_file.hunks.append(
                            self._build_hunk(current_hunk_start, current_hunk_lines)
                        )
                        current_hunk_lines = []

                    match = _HUNK_HEADER_RE.match(line)
                    if not match:
                        logger.warning("Could not parse hunk header: %r — skipping.", line)
                        i += 1
                        continue

                    new_start = int(match.group("new_start"))
                    current_hunk_start = new_start
                    line_cursor = new_start
                    i += 1
                    continue

                # -------------------------------------------------------
                # Diff content lines
                # -------------------------------------------------------
                if line == _NO_NEWLINE_MARKER:
                    i += 1
                    continue

                if current_file is None:
                    # Lines before the first "diff --git" header — skip
                    i += 1
                    continue

                if line.startswith(_ADDED_PREFIX):
                    # Added line — record it and advance the new-file cursor
                    current_hunk_lines.append(line_cursor)
                    line_cursor += 1

                elif line.startswith(_REMOVED_PREFIX):
                    # Removed line — does NOT advance the new-file cursor
                    pass

                elif line.startswith(_CONTEXT_PREFIX) or line == "":
                    # Context line — advance the new-file cursor
                    if current_hunk_lines or True:  # always track for range continuity
                        current_hunk_lines.append(line_cursor)
                    line_cursor += 1

                i += 1

        except Exception as exc:
            raise DiffParseError(
                f"Failed to parse unified diff at line {i}: {exc!r}"
            ) from exc

        # Finalise the last hunk of the last file
        if current_file is not None and current_hunk_lines:
            current_file.hunks.append(
                self._build_hunk(current_hunk_start, current_hunk_lines)
            )

        logger.info(
            "Diff parsed: %d files, %d total hunks.",
            len(file_diffs),
            sum(len(fd.hunks) for fd in file_diffs),
        )
        return file_diffs

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_diff_header(line: str) -> FileDiff:
        """
        Parse a ``diff --git a/<old> b/<new>`` line into a ``FileDiff``.

        Falls back to extracting the filename from the ``b/`` portion of the
        header if the regex does not match (handles exotic filenames with
        spaces in a best-effort manner).
        """
        match = _DIFF_HEADER_RE.match(line)
        if match:
            old_path = match.group("old_path")
            new_path = match.group("new_path")
        else:
            # Best-effort fallback for filenames with unusual characters
            parts = line.split(" b/", maxsplit=1)
            new_path = parts[1] if len(parts) == 2 else line
            old_path = new_path

        return FileDiff(filename=new_path, old_filename=old_path)

    @staticmethod
    def _build_hunk(start_line: int, line_numbers: list[int]) -> ModifiedHunk:
        """
        Construct a ``ModifiedHunk`` from the accumulated line numbers in a hunk.

        Args:
            start_line: The ``new_start`` value from the ``@@`` header.
            line_numbers: Ordered list of new-file line numbers in this hunk.

        Returns:
            A ``ModifiedHunk`` with contiguous start/end range.
        """
        if not line_numbers:
            return ModifiedHunk(start_line=start_line, end_line=start_line, line_count=0)

        return ModifiedHunk(
            start_line=min(line_numbers),
            end_line=max(line_numbers),
            line_count=len(line_numbers),
        )


def parse_diff(raw_diff: str) -> list[FileDiff]:
    """
    Module-level convenience function wrapping ``DiffParser.parse``.

    Prefer this for one-shot usage; instantiate ``DiffParser`` directly
    if parsing many diffs in a loop to avoid re-creating the object.

    Args:
        raw_diff: Raw unified diff string.

    Returns:
        List of ``FileDiff`` objects.
    """
    return DiffParser().parse(raw_diff)

