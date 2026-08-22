#!/usr/bin/env python3
"""Build a local, fetched-on-demand real-producer corpus for strypt.

The script intentionally has no Python-package dependencies.  It obtains public upstream
repositories into .cache/, copies a curated subset into real-corpus/, creates a few clearly
labelled structural fixtures, and regenerates manifests from the files actually present.
"""
from __future__ import annotations

import csv, hashlib, json, os, shutil, subprocess, sys
from collections import Counter
from pathlib import Path

import sanitise_corpus

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "real-corpus"
CACHE = ROOT / ".cache"
UPSTREAMS = {
    "exif-samples": "https://github.com/ianare/exif-samples.git",
    "sample-files": "https://github.com/py-pdf/sample-files.git",
    "codec-corpus": "https://github.com/imazen/codec-corpus.git",
}
DIRS = [
    *[f"jpeg/{x}" for x in ("iphone", "android", "canon", "sony", "nikon")],
    *[f"png/{x}" for x in ("browser", "macos", "windows", "linux", "design-tools")],
    *[f"webp/{x}" for x in ("browser", "chrome", "firefox", "android", "converters")],
    *[f"pdf/{x}" for x in ("latex", "word", "acrobat", "scanner")],
    *[f"generated/{x}" for x in ("jpeg", "png", "webp", "pdf")],
]
# destination, cache-relative input, producer, confidence, note
FILES = [
    # Device classifications are backed by embedded Exif Make/Model (except the iPhone HDR samples).
    *[(f"jpeg/canon/{n}", f"exif-samples/jpg/{n}", "Canon camera", "HIGH", "Exif Make/Model and MakerNote where present") for n in ("Canon_40D.jpg", "Canon_DIGITAL_IXUS_400.jpg", "Canon_PowerShot_S40.jpg", "Canon_40D_photoshop_import.jpg")],
    ("jpeg/canon/canon-ixus.jpg", "exif-samples/jpg/exif-org/canon-ixus.jpg", "Canon camera", "HIGH", "Exif-org camera sample"),
    ("jpeg/canon/22-canon_tags.jpg", "exif-samples/jpg/tests/22-canon_tags.jpg", "Canon camera", "HIGH", "MakerNote-focused upstream test sample"),
    *[(f"jpeg/nikon/{n}", f"exif-samples/jpg/{n}", "Nikon camera", "HIGH", "Exif Make/Model and MakerNote where present") for n in ("Nikon_COOLPIX_P1.jpg", "Nikon_D70.jpg")],
    ("jpeg/nikon/nikon-e950.jpg", "exif-samples/jpg/exif-org/nikon-e950.jpg", "Nikon camera", "HIGH", "Exif-org camera sample"),
    *[(f"jpeg/sony/{Path(n).name}", f"exif-samples/jpg/{n}", "Sony camera", "HIGH", "Exif Make/Model evidence") for n in ("Sony_HDR-HC3.jpg", "exif-org/sony-cybershot.jpg", "exif-org/sony-d700.jpg")],
    ("jpeg/sony/sony-powershota5.jpg", "exif-samples/jpg/exif-org/sony-powershota5.jpg", "Sony camera", "MEDIUM", "Exif-org sample; model metadata determines final evidence"),
    *[(f"jpeg/android/{n}", f"exif-samples/jpg/mobile/{n}", "Android camera", "HIGH", "Embedded HMD/Jolla device Make and Model") for n in ("HMD_Nokia_8.3_5G.jpg", "HMD_Nokia_8.3_5G_hdr.jpg", "jolla.jpg")],
    ("jpeg/android/Samsung_Digimax_i50_MP3.jpg", "exif-samples/jpg/Samsung_Digimax_i50_MP3.jpg", "Samsung camera", "HIGH", "Embedded Samsung Make/Model"),
    *[(f"jpeg/iphone/{n}", f"exif-samples/jpg/hdr/{n}", "Apple iPhone", "MEDIUM", "Upstream filename identifies iPhone HDR sample; inspect before public redistribution") for n in ("iphone_hdr_NO.jpg", "iphone_hdr_YES.jpg")],
    ("jpeg/iphone/IMG_5250.jpeg", "exif-samples/heic/IMG_5250.jpeg", "Apple iPhone", "MEDIUM", "Upstream original filename; validate embedded metadata"),
    # Real application/browser assets, evidence is upstream location and chunk inspection, not OS inference.
    *[(f"png/browser/{n}", f"codec-corpus/png-conformance/{n}", "web upload/browser asset", "MEDIUM", "Real Wikimedia upload retained by codec-corpus") for n in ("wm_upload_wikimedia_org_4edbe895c4c29af5.png", "wm_upload_wikimedia_org_f14b0faca19b77e2.png", "Disable_auto_recalculation_26.png")],
    *[(f"png/browser/{n}", f"codec-corpus/png-conformance/{n}", "web upload/browser asset", "MEDIUM", "Real Wikimedia upload retained by codec-corpus") for n in ("wm_upload_wikimedia_org_a23d1e831e128dff.png", "wm_upload_wikimedia_org_c8a458b0cef3d942.png")],
    *[(f"png/design-tools/{n}", f"codec-corpus/imageflow/test_inputs/{n}", "design/image-processing application", "MEDIUM", "Real application test input; producer not asserted beyond upstream evidence") for n in ("frymire.png", "rings2.png", "red-night.png", "gradients.png", "whitespace-issue.png")],
    *[(f"png/linux/{n}", f"codec-corpus/image-rs/test-images/png/{n}", "Linux open-source corpus asset", "LOW", "Useful real/conformance asset; desktop producer unverified") for n in ("transparency/acid2.png", "bugfixes/issue#2026.png", "interlaced/basi2c08.png", "16bpc/basn6a16.png")],
    *[(f"png/macos/{n}", f"codec-corpus/imageflow/test_inputs/{n}", "desktop screenshot/application asset", "LOW", "No producer claim; category is a targeted local coverage bucket") for n in ("31182064-e1c54784-a8f0-11e7-8bb3-833bba872975.png", "png_turns_empty_2.png")],
    *[(f"png/macos/{n}", f"codec-corpus/imageflow/test_inputs/{n}", "desktop screenshot/application asset", "LOW", "No producer claim; category is a targeted local coverage bucket") for n in ("shirt_transparent.png", "whitespace-issue.png", "dice.png")],
    *[(f"png/windows/{n}", f"codec-corpus/png-conformance/{n}", "desktop application asset", "LOW", "No producer claim; validates chunk diversity") for n in ("14b47384-7042-11e5-801d-804da7b4cbe6.png", "wm_upload_wikimedia_org_a23d1e831e128dff.png")],
    *[(f"png/windows/{n}", f"codec-corpus/png-conformance/{n}", "desktop application asset", "LOW", "No producer claim; validates chunk diversity") for n in ("wm_upload_wikimedia_org_3a9fa5185de5c6c8.png", "wm_upload_wikimedia_org_45634e241d7821a3.png", "wm_upload_wikimedia_org_f6c96971fbd1da0d.png")],
    *[(f"webp/converters/{n}", f"codec-corpus/imageflow/test_inputs/{n}", "Imageflow/libwebp conversion", "HIGH", "Upstream Imageflow conversion input") for n in ("1_webp_a.webp", "1_webp_ll.webp", "5_webp_ll.webp", "lossy_mountain.webp")],
    ("webp/converters/codec-conformance-simple.webp", "codec-corpus/webp-conformance/valid/simple.webp", "WebP reference encoder", "MEDIUM", "Conformance producer, not attributed to a browser"),
    *[(f"webp/browser/{n}", f"codec-corpus/image-rs/test-images/webp/{n}", "browser/web asset", "MEDIUM", "Upstream test asset; exact browser encoder not asserted") for n in ("lossy_images/simple-rgb.webp", "lossless_images/simple_xmp.webp", "extended_images/anim.webp")],
    *[(f"webp/browser/{Path(n).name}", f"codec-corpus/image-rs/test-images/webp/{n}", "browser/web asset", "MEDIUM", "Upstream test asset; exact browser encoder not asserted") for n in ("lossy_images/simple-gray.webp", "extended_images/lossy_alpha.webp")],
    *[(f"webp/chrome/{n}", f"codec-corpus/webp-conformance/valid/{n}", "WebP reference encoder", "MEDIUM", "Encoder settings encoded in upstream filename; not claimed Chrome-produced") for n in ("src_grad_16_q90_m4_ff0_def.webp", "src_noise_q0_m0_def_def.webp", "advertises_rgba_but_frames_are_rgb.webp")],
    *[(f"webp/chrome/{n}", f"codec-corpus/webp-conformance/valid/{n}", "WebP reference encoder", "MEDIUM", "Encoder settings encoded in upstream filename; not claimed Chrome-produced") for n in ("src_checker_odd_q0_m4_def_def.webp", "src_noise_q90_m4_ff50strong_def.webp")],
    *[(f"webp/firefox/{n}", f"codec-corpus/webp-conformance/valid/{n}", "WebP reference/conformance asset", "LOW", "Coverage bucket only; no unsupported Firefox producer claim") for n in ("anim.webp", "src_checker_odd_q50_m0_ff0_def.webp")],
    *[(f"webp/firefox/{n}", f"codec-corpus/webp-conformance/valid/{n}", "WebP reference/conformance asset", "LOW", "Coverage bucket only; no unsupported Firefox producer claim") for n in ("lossy_alpha.webp", "simple_xmp.webp", "multi-color.webp")],
    *[(f"webp/android/{n}", f"codec-corpus/webp-conformance/valid/{n}", "WebP reference/conformance asset", "LOW", "Coverage bucket only; no unsupported Android producer claim") for n in ("src_grad_16_q0_m4_ff50strong_def.webp", "src_noise_q90_m4_def_def.webp")],
    *[(f"webp/android/{n}", f"codec-corpus/webp-conformance/valid/{n}", "WebP reference/conformance asset", "LOW", "Coverage bucket only; no unsupported Android producer claim") for n in ("2-color.webp", "simple-gray.webp", "src_noise_q50_m0_ff0_def.webp")],
    *[(f"pdf/latex/{d}.pdf", f"sample-files/{d}/{n}", "pdfLaTeX", "HIGH", "Directory and source project explicitly identify pdfLaTeX") for d,n in (("003-pdflatex-image","pdflatex-image.pdf"),("004-pdflatex-4-pages","pdflatex-4-pages.pdf"),("006-pdflatex-outline","pdflatex-outline.pdf"),("010-pdflatex-forms","pdflatex-forms.pdf"),("026-latex-multicolumn","multicolumn.pdf"))],
    *[(f"pdf/latex/{Path(n).stem}.pdf", f"sample-files/{d}/{n}", "pdfLaTeX", "HIGH", "Directory and source project explicitly identify pdfLaTeX") for d,n in (("009-pdflatex-geotopo","GeoTopo.pdf"),("009-pdflatex-geotopo","GeoTopo-komprimiert.pdf"))],
    *[(f"pdf/word/{d}.pdf", f"sample-files/{d}/{n}", "LibreOffice Writer", "HIGH", "Explicit upstream directory; intentionally not misclassified as Word") for d,n in (("002-trivial-libre-office-writer","002-trivial-libre-office-writer.pdf"),("012-libreoffice-form","libreoffice-form.pdf"),("016-libre-office-link","libre-office-link.pdf"),("005-libreoffice-writer-password","libreoffice-writer-password.pdf"))],
    ("pdf/word/011-google-doc-document.pdf", "sample-files/011-google-doc-document/google-doc-document.pdf", "Google Docs", "HIGH", "Explicit upstream producer directory; retained in requested office bucket"),
    *[(f"pdf/acrobat/{d}.pdf", f"sample-files/{d}/{n}", "PDF producer (inspect metadata)", "MEDIUM", "Real sample; source does not establish Acrobat provenance") for d,n in (("020-xmp","output_with_metadata_pymupdf.pdf"),("024-annotations","annotated_pdf.pdf"),("025-attachment","with-attachment.pdf"))],
    *[(f"pdf/acrobat/{d}.pdf", f"sample-files/{d}/{n}", "PDF producer (inspect metadata)", "MEDIUM", "Real sample; source does not establish Acrobat provenance") for d,n in (("021-pdfa","crazyones-pdfa.pdf"),("027-cropped-rotated-scaled","cropped-rotated-scaled.pdf"))],
    *[(f"pdf/scanner/{d}.pdf", f"sample-files/{d}/{n}", "image/scanned-document style PDF", "LOW", "Useful image-heavy real sample; scanner producer unverified") for d,n in (("007-imagemagick-images","imagemagick-images.pdf"),("019-grayscale-image","grayscale-image.pdf"))],
    *[(f"pdf/scanner/{Path(n).stem}.pdf", f"sample-files/{d}/{n}", "image/scanned-document style PDF", "LOW", "Useful image-heavy real sample; scanner producer unverified") for d,n in (("007-imagemagick-images","imagemagick-ASCII85Decode.pdf"),("007-imagemagick-images","imagemagick-CCITTFaxDecode.pdf"),("007-imagemagick-images","imagemagick-lzw.pdf"))],
]

def run(*args):
    return subprocess.run(args, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout

def acquire():
    CACHE.mkdir(exist_ok=True)
    for name, url in UPSTREAMS.items():
        d=CACHE/name
        if not d.exists():
            print("cloning", name); subprocess.run(["git","clone","--depth","1",url,str(d)], check=True)

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def fmt_for(p):
    b=p.read_bytes()[:16]
    return "JPEG" if b.startswith(b"\xff\xd8\xff") else "PNG" if b.startswith(b"\x89PNG") else "WebP" if b.startswith(b"RIFF") and b[8:12]==b"WEBP" else "PDF" if b.startswith(b"%PDF-") else "unknown"
# -Creator is deliberately absent. On a PDF it frequently holds a natural person's name
# ("Martin Thoma", "Dr. Guido Hegasy" in the current sample set), and MANIFEST.csv is the one
# part of this corpus that is committed — so reading it here would put exactly the personal
# data docs/TESTING_STRATEGY.md §3 forbids into git history, via the manifest rather than via
# a fixture. -Producer names the writing software, not a person, and is what the coverage
# buckets actually need. Make/Model are device identifiers, not personal ones.
def exif(p): return run("exiftool","-s3","-ImageWidth","-ImageHeight","-Make","-Model","-LensModel","-Orientation","-ProfileDescription","-Producer","-PDFVersion","-PageCount",str(p)).replace("\n", "; ").strip()
def dimensions(p, f):
    out=run("identify","-format","%w %h",str(p)).strip().split()
    if len(out)>=2 and f != "PDF": return out[0],out[1]
    if f=="PDF":
        o=run("pdfinfo",str(p)); pages=next((x.split(":",1)[1].strip() for x in o.splitlines() if x.startswith("Pages:")),"")
        return "", pages
    return "", ""
def validate(p,f):
    if p.stat().st_size==0 or b"<html" in p.read_bytes()[:512].lower(): return "rejected: empty or HTML"
    if f=="PDF":
        q=subprocess.run(["qpdf","--check",str(p)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return "valid" if q.returncode == 0 else "malformed-but-useful: qpdf --check failed"
    result=subprocess.run(["identify",str(p)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return "valid" if result.returncode == 0 else "malformed-but-useful: decoder rejected"
# Everything generated() produces, corpus-relative to generated/. prune() needs this to tell
# a current fixture from one left behind by an earlier version of this script.
GENERATED_NAMES = (
    "jpeg/progressive.jpg", "jpeg/subsampling-444.jpg", "jpeg/progressive-truncated.jpg",
    "png/interlaced.png", "png/palette.png", "png/interlaced-truncated.png",
    "webp/lossless-alpha.webp", "webp/lossy.webp", "webp/lossy-truncated.webp",
    "webp/from-jpeg-exif.webp",
    "pdf/minimal-xref-table.pdf",
)

# Produced only with --with-browser, but listed here unconditionally so prune() never deletes
# it: regenerating needs a browser on the machine, which a later plain rebuild may not have.
BROWSER_NAMES = ("webp/browser/chrome-canvas.webp",)

# generated() files whose producer is worth stating precisely. Without this every generated
# fixture is manifested as the same anonymous "generated locally", which would hide the whole
# point of the two WebP entries below — that a named real encoder produced them.
GENERATED_META = {
    "generated/webp/from-jpeg-exif.webp": (
        "libwebp cwebp (JPEG->WebP conversion)", "GENERATED",
        "Real Canon Exif and ICC carried across a format conversion by cwebp -metadata all; "
        "closes the conversion-path gap in docs/THREAT_MODEL.md 7.4",
    ),
}

# Set by browser_webp() so MANIFEST.md can name the encoder without putting the file in
# MANIFEST.csv. See manifests().
BROWSER_NOTE = ""


def write_minimal_xref_pdf(path):
    """The smallest document with a correct classic cross-reference table.

    This replaces a fixture previously called ``minimal-object-stream.pdf``, which was wrong
    twice over: it contained no object stream of any kind, and its ``startxref`` was
    hardcoded to 105 while the ``xref`` keyword sat at offset 96, so every parser refused it.
    A fixture that fails for a reason unrelated to its name teaches the reader the wrong
    lesson about the handler.

    Offsets are computed rather than hardcoded, which is why that class of mistake cannot
    recur here. Genuine PDF 1.5 object-stream and cross-reference-stream coverage comes from
    the fetched pdf/latex fixtures — GeoTopo.pdf carries 34 object streams.
    """
    objs={1:b"<</Type/Catalog/Pages 2 0 R>>", 2:b"<</Type/Pages/Count 0/Kids[]>>"}
    out=bytearray(b"%PDF-1.5\n"); offsets={}
    for n in sorted(objs):
        offsets[n]=len(out); out+=b"%d 0 obj" % n + objs[n] + b"endobj\n"
    startxref=len(out)
    out+=b"xref\n0 %d\n" % (max(objs)+1) + b"0000000000 65535 f \n"
    for n in sorted(objs): out+=b"%010d 00000 n \n" % offsets[n]
    out+=b"trailer<</Size %d /Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n" % (max(objs)+1, startxref)
    path.write_bytes(bytes(out))


def generated():
    # A compact local base then encoder-produced variants plus safely marked truncations.
    # ImageMagick stamps the wall clock into generated PNGs in two separate places: the
    # date:create/date:modify/date:timestamp tEXt chunks, and the tIME chunk. Both must be
    # excluded, or the files differ on every run and every sha256 in MANIFEST.csv goes stale.
    # Excluding only "date" leaves tIME behind and looks fixed without being fixed.
    NODATE=["-define","png:exclude-chunk=date,time"]
    base=ROOT/".generated-base.png"; run("magick","-size","33x17","gradient:#204060-#e0c080",*NODATE,str(base))
    generated=[("jpeg/progressive.jpg", ["magick",str(base),"-interlace","Plane",str(CORPUS/"generated/jpeg/progressive.jpg")]),("jpeg/subsampling-444.jpg",["magick",str(base),"-sampling-factor","4:4:4",str(CORPUS/"generated/jpeg/subsampling-444.jpg")]),("png/interlaced.png",["magick",str(base),"-interlace","PNG",*NODATE,str(CORPUS/"generated/png/interlaced.png")]),("png/palette.png",["magick",str(base),"-colors","8",*NODATE,str(CORPUS/"generated/png/palette.png")]),("webp/lossless-alpha.webp",["cwebp","-lossless",str(base),"-o",str(CORPUS/"generated/webp/lossless-alpha.webp")]),("webp/lossy.webp",["cwebp","-q","37",str(base),"-o",str(CORPUS/"generated/webp/lossy.webp")])]
    for _,cmd in generated: subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    write_minimal_xref_pdf(CORPUS/"generated/pdf/minimal-xref-table.pdf")
    for f in ("jpeg/progressive.jpg","png/interlaced.png","webp/lossy.webp"):
        src=CORPUS/"generated"/f; (src.parent/(src.stem+"-truncated"+src.suffix)).write_bytes(src.read_bytes()[:max(8,src.stat().st_size//2)])
    base.unlink(missing_ok=True)

    # The format-conversion path: metadata surviving a change of container. Every other WebP
    # here was born a WebP, so none of them exercises the case where a camera's Exif — and its
    # embedded thumbnail, which is a picture of the original scene — is carried into a new
    # format by a converter. cwebp -metadata all does exactly that, and it is the reference
    # libwebp encoder rather than a synthetic stand-in.
    #
    # The source is a real Canon JPEG already in the corpus, so the Exif is genuine (Make,
    # Model, DateTimeOriginal, IFD1 thumbnail). That also means this file inherits the same
    # do-not-commit status as the rest of real-corpus/.
    src_jpeg = CORPUS/"jpeg/canon/Canon_40D.jpg"
    if src_jpeg.exists():
        run("cwebp","-quiet","-metadata","all","-q","80",str(src_jpeg),
            "-o",str(CORPUS/"generated/webp/from-jpeg-exif.webp"))
    else:
        print("SKIP generated/webp/from-jpeg-exif.webp — source JPEG missing")


CHROME_PATHS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
)
# Canvas export is synchronous, so the DOM carries the finished data: URL by dump time.
BROWSER_PAGE = """<!doctype html><body><script>
var c=document.createElement('canvas');c.width=120;c.height=80;
var x=c.getContext('2d');
var g=x.createLinearGradient(0,0,120,80);
g.addColorStop(0,'#204060');g.addColorStop(1,'#e0c080');
x.fillStyle=g;x.fillRect(0,0,120,80);
for(var i=0;i<400;i++){x.fillStyle='rgba('+(i*7%256)+','+(i*13%256)+','+(i*29%256)+',0.8)';
x.fillRect((i*17)%120,(i*31)%80,3,3);}
document.body.textContent=c.toDataURL('image/webp',0.8);
</script></body>"""


def browser_webp():
    """Produce a WebP actually encoded by a browser.

    OFF BY DEFAULT, and the reason is manifest churn. MANIFEST.csv is committed and is supposed
    to round-trip, but browsers auto-update every few weeks and a new encoder build changes the
    bytes. Wiring this into every rebuild would leave `git status` dirty on any machine whose
    Chrome differs from whoever regenerated the manifest last — the file would be recording the
    contributor's browser version rather than the corpus.

    So it is opt-in, and prune() is told to leave the result alone.
    """
    import base64, re, signal, tempfile
    exe = next((p for p in CHROME_PATHS if os.path.exists(p)), None)
    if not exe:
        print("SKIP browser WebP — no Chrome/Chromium found"); return
    ver = subprocess.run([exe,"--version"],stdout=subprocess.PIPE,text=True).stdout.strip()
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp)/"gen.html"; page.write_text(BROWSER_PAGE)
        # --headless does not always exit on its own after --dump-dom; kill it rather than
        # letting a rebuild hang forever on a machine where it does not.
        proc = subprocess.Popen(
            [exe,"--headless=old","--disable-gpu","--no-sandbox","--disable-background-networking",
             "--no-first-run","--disable-default-apps","--virtual-time-budget=3000",
             f"--user-data-dir={tmp}/profile","--dump-dom",page.as_uri()],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try: dom,_ = proc.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            proc.kill(); dom,_ = proc.communicate()
    m = re.search(r"data:image/webp;base64,([A-Za-z0-9+/=]+)", dom or "")
    if not m:
        print("SKIP browser WebP — browser produced no WebP data URL"); return
    out = CORPUS/"webp/browser/chrome-canvas.webp"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(base64.b64decode(m.group(1)))
    global BROWSER_NOTE
    BROWSER_NOTE = f"{ver} canvas.toDataURL('image/webp'), {out.stat().st_size} bytes"
    print(f"browser WebP written by {ver} ({out.stat().st_size} bytes)")

def manifests():
    # BROWSER_NAMES are deliberately excluded from MANIFEST.csv. The manifest is committed and
    # is meant to round-trip: a rebuild on any machine should reproduce it. A browser-encoded
    # file cannot satisfy that — browsers auto-update, and a machine without a browser cannot
    # produce the row at all, so including it would leave `git status` dirty for everyone whose
    # setup differs from whoever regenerated it last. MANIFEST.md names the file and its
    # encoder instead, so the corpus does not silently contain something undocumented.
    rows=[]; hashes={}
    skip={"MANIFEST.csv","MANIFEST.md","SOURCES.md","README.md"}
    for p in sorted(x for x in CORPUS.rglob("*") if x.is_file() and x.name not in skip
                    and x.relative_to(CORPUS).as_posix() not in BROWSER_NAMES):
        rel=p.relative_to(CORPUS).as_posix(); f=fmt_for(p); parts=rel.split("/"); gen=parts[0]=="generated"; meta=exif(p); w,h=dimensions(p,f); status=validate(p,f); source="locally generated" if gen else "https://github.com/"+("ianare/exif-samples" if "jpeg/" in rel else "imazen/codec-corpus" if f in {"PNG","WebP"} else "py-pdf/sample-files")
        producer="generated locally" if gen else "upstream sample"; confidence="GENERATED" if gen else "LOW"; note="clearly labelled generated edge case" if gen else ""
        source_path="generated locally" if gen else "not mapped"
        for d,s,prod,c,n in FILES:
            if d==rel: producer,confidence,note,source_path=prod,c,n,s; break
        # Overrides FILES as well as the defaults: these files are produced here, so the
        # upstream URL inferred from their format above would name a repository they never
        # came from.
        if rel in GENERATED_META:
            producer,confidence,note = GENERATED_META[rel]
            source=source_path="locally generated"
        digest=sha(p); hashes.setdefault(digest,[]).append(rel)
        rows.append(dict(path=rel,format=f,producer=producer,producer_model="",producer_version="",source=source,source_path=source_path,license="see upstream repository",provenance_confidence=confidence,sha256=digest,size_bytes=p.stat().st_size,width=w,height=h,metadata_summary=meta,validation_status=status,notes=note))
    fields=list(rows[0]) if rows else []
    # lineterminator="\n": csv defaults to CRLF, which Git normalises to LF on commit, so the
    # committed manifest would differ from the one a rebuild produces and `git status` would
    # be dirty after every run. The point of committing it is that it round-trips.
    with (CORPUS/"MANIFEST.csv").open("w",newline="") as out:
        w=csv.DictWriter(out,fieldnames=fields,lineterminator="\n"); w.writeheader(); w.writerows(rows)
    counts=Counter(r["format"] for r in rows); cats=Counter("/".join(r["path"].split("/")[:2]) for r in rows); prov=Counter(r["provenance_confidence"] for r in rows)
    # The browser fixture is described statically in README.md below, not here: naming it with
    # its version would move the churn problem from MANIFEST.csv to MANIFEST.md, and omitting
    # it only when absent would churn too. The build prints the version to stdout instead.
    browser_line = ""
    (CORPUS/"MANIFEST.md").write_text("# Real-producer corpus manifest\n\n- Total fixtures: %d\n- Total size: %d bytes\n- By format: %s\n- By category: %s\n- Provenance: %s\n- Malformed-but-useful: %d\n- Duplicate hashes: %d\n\nMetadata and validation details are in `MANIFEST.csv`. Generated fixtures are never presented as producer output.\n%s"%(len(rows),sum(int(r['size_bytes']) for r in rows),dict(counts),dict(cats),dict(prov),sum('malformed-but-useful' in r['validation_status'] for r in rows),sum(len(v)-1 for v in hashes.values() if len(v)>1),browser_line))
    (CORPUS/"SOURCES.md").write_text("# Sources\n\n- [ianare/exif-samples](https://github.com/ianare/exif-samples): camera/device JPEG samples; upstream licensing/provenance applies.\n- [imazen/codec-corpus](https://github.com/imazen/codec-corpus): imageflow, image-rs, PNG/WebP conformance and real-world assets; see per-dataset licenses.\n- [py-pdf/sample-files](https://github.com/py-pdf/sample-files): PDF producer samples, CC-BY-SA-4.0.\n\nExact source-relative paths and confidence notes are represented in the collector table and manifest.\n")
    (CORPUS/"README.md").write_text("# Local real-producer corpus\n\nA fetched-on-demand engineering corpus for strypt, separate from the committed synthetic fixture corpus. It exercises producer quirks and makes no claim that generated files are real. Run `python3 build_real_corpus.py` from this directory to acquire sources (if absent), copy curated fixtures, validate them, and regenerate manifests. Files with weak provenance are explicitly marked LOW; categories are coverage buckets, not unsupported producer assertions.\n\n**Every build sanitises before it writes manifests** (`sanitise_corpus.py`). The upstream files carry real named people, a real camera serial and live GPS; those values are replaced with synthetic ones while the producer's structure is preserved, because the structure is the whole reason to keep a real-producer fixture. The build aborts rather than write a manifest if verification fails. Do not disable this: the copy step restores pristine upstream bytes on every run, so skipping sanitisation silently reinstates the real data.\n\n`webp/browser/chrome-canvas.webp` is built only by `--with-browser` and is deliberately absent from `MANIFEST.csv`: it is encoded by the local browser, whose output changes on every auto-update, so a committed row for it could not round-trip on another machine. The build prints the exact browser version when it writes the file.\n")
    return rows, hashes
def prune():
    """Delete corpus files this script no longer produces.

    Without this, renaming or dropping an entry in FILES leaves the old file behind, and it
    keeps being manifested and tested as though it were still curated. That had already
    happened once: ``pdf/latex/009-pdflatex-geotopo.pdf`` survived a rename and sat in the
    tree as an unlisted byte-identical duplicate of ``GeoTopo-komprimiert.pdf``, inflating
    both the fixture count and the duplicate count.

    A rebuild should reproduce the corpus exactly, not accumulate it.
    """
    expected={d for d,*_ in FILES} | {f"generated/{n}" for n in GENERATED_NAMES} | set(BROWSER_NAMES)
    for p in sorted(CORPUS.rglob("*")):
        if not p.is_file(): continue
        rel=p.relative_to(CORPUS).as_posix()
        if rel in ("MANIFEST.csv","MANIFEST.md","README.md","SOURCES.md") or rel in expected: continue
        print("pruning unlisted",rel); p.unlink()


def main():
    for d in DIRS: (CORPUS/d).mkdir(parents=True,exist_ok=True)
    acquire()
    for dst,src,*_ in FILES:
        inp=CACHE/src; out=CORPUS/dst
        out.parent.mkdir(parents=True, exist_ok=True)
        if inp.exists() and (not out.exists() or sha(inp)!=sha(out)): shutil.copy2(inp,out)
        elif not inp.exists(): print("SOURCE FAILURE",src)
    generated()
    if "--with-browser" in sys.argv: browser_webp()
    # Sanitisation runs BEFORE manifests, and cannot be skipped.
    #
    # The copy loop above restores the pristine upstream bytes whenever they differ from what is
    # on disk, so without this the next build would quietly reinstate the real names, the camera
    # serial and the live GPS. Manifests must also be generated afterwards, or every sha256 in
    # MANIFEST.csv would describe a file that no longer exists on disk.
    if sanitise_corpus.sanitise(): sys.exit("sanitisation failed; refusing to write manifests")
    if sanitise_corpus.verify(): sys.exit("sanitisation verification failed; refusing to write manifests")
    prune(); rows, hashes=manifests(); print(f"fixtures={len(rows)} bytes={sum(int(r['size_bytes']) for r in rows)} duplicates={sum(len(v)-1 for v in hashes.values() if len(v)>1)}")
if __name__ == "__main__": main()
