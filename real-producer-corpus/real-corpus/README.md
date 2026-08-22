# Local real-producer corpus

A fetched-on-demand engineering corpus for strypt, separate from the committed synthetic fixture corpus. It exercises producer quirks and makes no claim that generated files are real. Run `python3 build_real_corpus.py` from this directory to acquire sources (if absent), copy curated fixtures, validate them, and regenerate manifests. Files with weak provenance are explicitly marked LOW; categories are coverage buckets, not unsupported producer assertions.

**Every build sanitises before it writes manifests** (`sanitise_corpus.py`). The upstream files carry real named people, a real camera serial and live GPS; those values are replaced with synthetic ones while the producer's structure is preserved, because the structure is the whole reason to keep a real-producer fixture. The build aborts rather than write a manifest if verification fails. Do not disable this: the copy step restores pristine upstream bytes on every run, so skipping sanitisation silently reinstates the real data.

`webp/browser/chrome-canvas.webp` is built only by `--with-browser` and is deliberately absent from `MANIFEST.csv`: it is encoded by the local browser, whose output changes on every auto-update, so a committed row for it could not round-trip on another machine. The build prints the exact browser version when it writes the file.
