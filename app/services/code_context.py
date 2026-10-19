import os
from typing import Optional


def extract_code_context(
    target_dir: str,
    file_path: str,
    line_number: int,
    context_lines: int = 5,
) -> Optional[str]:
    """
    Extracts ±context_lines lines around line_number from file_path inside target_dir.
    Returns a formatted string with line numbers; the flagged line is marked with '<-- FLAGGED'.
    Returns None if the file cannot be read (binary, missing, encoding errors).
    """
    if not file_path or not line_number:
        return None

    full_path = os.path.join(target_dir, file_path.lstrip("/\\"))
    if not os.path.isfile(full_path):
        return None

    try:
        with open(full_path, "r", encoding="utf-8", errors="strict") as fh:
            all_lines = fh.readlines()
    except (UnicodeDecodeError, OSError):
        return None

    total = len(all_lines)
    # line_number is 1-based
    zero_idx = line_number - 1
    start = max(0, zero_idx - context_lines)
    end = min(total, zero_idx + context_lines + 1)

    parts = []
    for i in range(start, end):
        lineno = i + 1
        content = all_lines[i].rstrip("\n")
        marker = "  <-- FLAGGED" if lineno == line_number else ""
        parts.append(f"{lineno:4d}: {content}{marker}")

    return "\n".join(parts) if parts else None
