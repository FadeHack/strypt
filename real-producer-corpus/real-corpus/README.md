# Local real-producer corpus

A fetched-on-demand engineering corpus for strypt, separate from the committed synthetic fixture corpus. It exercises producer quirks and makes no claim that generated files are real. Run `python3 build_real_corpus.py` from this directory to acquire sources (if absent), copy curated fixtures, validate them, and regenerate manifests. Files with weak provenance are explicitly marked LOW; categories are coverage buckets, not unsupported producer assertions.

`webp/browser/chrome-canvas.webp` is built only by `--with-browser` and is deliberately absent from `MANIFEST.csv`: it is encoded by the local browser, whose output changes on every auto-update, so a committed row for it could not round-trip on another machine. The build prints the exact browser version when it writes the file.
