"""
Assemble a review prompt by reading a template .md file
and injecting code from .py files at marked locations.

Usage:
    python tools/assemble_review.py \
        --template docs/audit_pack/GEMINI3_REVIEW_PROMPT.md \
        --output review_for_gemini.txt

The template should contain markers like:
    === guardian/main.py ===
    [PASTE]

The script replaces [PASTE] with the actual file contents.
It also supports a simpler format:
    [FILE: guardian/main.py]
which gets replaced with the file contents.

Output is a single text file ready to copy-paste into
Gemini, ChatGPT, or any reviewer.
"""
import argparse
import re
from pathlib import Path


def assemble(template_path: str, output_path: str, repo_root: str = "."):
    root = Path(repo_root)
    template = Path(template_path).read_text(encoding="utf-8")

    # Pattern 1: === path/to/file.py ===\n[PASTE]
    def replace_paste_block(match):
        filepath = match.group(1).strip()
        full_path = root / filepath
        if full_path.exists():
            content = full_path.read_text(encoding="utf-8")
            return f"=== {filepath} ===\n```python\n{content}\n```"
        else:
            return f"=== {filepath} ===\n[FILE NOT FOUND: {full_path}]"

    paste_count = len(re.findall(r'\[PASTE\]', template))
    result = re.sub(
        r'===\s*(.+?)\s*===\s*\r?\n\s*\[PASTE\]',
        replace_paste_block,
        template,
    )
    replaced_count = paste_count - len(re.findall(r'\[PASTE\]', result))
    print(f"  [PASTE] markers found: {paste_count}, replaced: {replaced_count}")
    if replaced_count == 0 and paste_count > 0:
        print(f"  DEBUG first 200 chars of template: {repr(template[:200])}")

    # Pattern 2: [FILE: path/to/file.py]
    def replace_file_tag(match):
        filepath = match.group(1).strip()
        full_path = root / filepath
        if full_path.exists():
            content = full_path.read_text(encoding="utf-8")
            return f"```python\n{content}\n```"
        else:
            return f"[FILE NOT FOUND: {full_path}]"

    result = re.sub(
        r'\[FILE:\s*(.+?)\]',
        replace_file_tag,
        result,
    )

    # Write output
    output = Path(output_path)
    output.write_text(result, encoding="utf-8")

    # Stats
    file_count = len(re.findall(r'```python', result))
    total_lines = result.count('\n')
    print(f"Assembled: {output_path}")
    print(f"  Files injected: {file_count}")
    print(f"  Total lines: {total_lines}")
    print(f"  Size: {len(result):,} chars")

    # Warn if too large for typical context windows
    approx_tokens = len(result) // 4
    if approx_tokens > 100000:
        print(f"  WARNING: ~{approx_tokens:,} tokens — may exceed context window")
        print(f"  Consider splitting into multiple review passes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Assemble review prompt with code files"
    )
    parser.add_argument("--template", required=True,
                        help="Path to review prompt template (.md)")
    parser.add_argument("--output", required=True,
                        help="Output file path (.txt)")
    parser.add_argument("--repo", default=".",
                        help="Repository root (default: current dir)")
    args = parser.parse_args()
    assemble(args.template, args.output, args.repo)
