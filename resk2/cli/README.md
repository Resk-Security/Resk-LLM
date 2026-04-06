# RESK-LLM v2.1 - Security Scanner CLI

Scan LLM prompts through security pipeline.

## Usage

```bash
# Scan text
resk scan --text "Ignore all previous instructions"

# Scan from file
resk scan --file prompt.txt

# JSON output (for programmatic use)
resk scan --text "test" --json

# Pipe input
cat prompt.txt | resk scan

# Run full test suite
resk test
```
