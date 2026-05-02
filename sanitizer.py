import os, uuid, hashlib, re
from pathlib import Path
from urllib.parse import urlparse
from pikepdf import Pdf, Name
from db import get_db, init_db

# ================= CONFIG =================
# ✅ new (portable)
BASE_DIR = str((Path(__file__).parent / "data").resolve())

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
OUTPUT_DIR = os.path.join(BASE_DIR, "sanitized")
DB_PATH = os.path.join(BASE_DIR, "db", "cdr.db")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

init_db(DB_PATH)

# ================= HASH =================
def compute_sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# ================= SCORING =================
def score(item):
    s = item.lower()
    if "javascript" in s: return 90
    if "launch" in s: return 90
    if "openaction" in s: return 85
    if "embedded" in s: return 80
    if "action" in s: return 70
    if "uri" in s or "link" in s: return 40
    if "annot" in s: return 30
    if "metadata" in s: return 20
    return 10

def risk(score):
    if score >= 70: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"

# ================= URL DEFANG =================
def defang_url(url: str) -> str:
    """
    Defang URLs by replacing '.' with '[.]' and ':' with '[:]'
    """
    if not url:
        return url
    url = url.replace(".", "[.]")
    url = url.replace(":", "[:]")
    return url

# ================= IOC EXTRACTION =================
URL_REGEX = re.compile(rb'https?://[^\s<>()"]+')
IP_REGEX = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def extract_iocs_from_bytes(data: bytes):
    urls, ips = set(), set()

    for m in URL_REGEX.findall(data):
        url = m.decode(errors="ignore")
        urls.add(url)
        parsed = urlparse(url)
        if parsed.hostname and IP_REGEX.match(parsed.hostname.encode()):
            ips.add(parsed.hostname)

    for m in IP_REGEX.findall(data):
        ips.add(m.decode())

    return urls, ips

def extract_domains(urls):
    return {urlparse(u).hostname for u in urls if urlparse(u).hostname}

# ================= REPORT =================
class CDRReport:
    def __init__(self, scan_id, db):
        self.scan_id = scan_id
        self.db = db
        self.total_score = 0
        self.group_id = str(uuid.uuid4())

    def found(self, item, location, reason):
        s = score(item)
        self.total_score += s
        self.db.execute("""
            INSERT INTO detections
            (scan_id, item, location, reason, score, action, group_id)
            VALUES (?, ?, ?, ?, ?, 'FOUND', ?)
        """, (self.scan_id, item, location, str(reason), s, self.group_id))

    def removed(self, item, location, reason):
        self.db.execute("""
            INSERT INTO detections
            (scan_id, item, location, reason, score, action, group_id)
            VALUES (?, ?, ?, ?, 0, 'REMOVED', ?)
        """, (self.scan_id, item, location, str(reason), self.group_id))

# ================= SANITIZER =================
def sanitize_pdf(input_pdf):
    db = get_db()

    sha256 = compute_sha256(input_pdf)
    if db.execute("SELECT 1 FROM scans WHERE sha256=?", (sha256,)).fetchone():
        return None

    output_pdf = os.path.join(
        OUTPUT_DIR,
        Path(input_pdf).stem + "_SANITIZED.pdf"
    )

    cur = db.execute("""
        INSERT INTO scans
        (original_filename, sanitized_filename, input_path,
         output_path, total_score, sha256, risk_level)
        VALUES (?, ?, ?, ?, 0, ?, 'PENDING')
    """, (
        Path(input_pdf).name,
        Path(output_pdf).name,
        input_pdf,
        output_pdf,
        sha256
    ))

    scan_id = cur.lastrowid
    report = CDRReport(scan_id, db)

    # ================= IOC SCAN =================
    raw_bytes = Path(input_pdf).read_bytes()
    urls, ips = extract_iocs_from_bytes(raw_bytes)
    domains = extract_domains(urls)

    for url in urls:
        report.found("External URL", "PDF Binary", defang_url(url))

    for ip in ips:
        report.found("External IP", "PDF Binary", ip)

    for d in domains:
        report.found("Domain", "PDF Binary", d)

    # ================= HARD PDF NEUTRALIZATION =================
    with Pdf.open(input_pdf) as pdf:
        root = pdf.Root

        if Name.OpenAction in root:
            report.removed("OpenAction", "Catalog", "Removed")
            del root[Name.OpenAction]

        if Name.Metadata in root:
            report.removed("Metadata", "Catalog", "Removed")
            del root[Name.Metadata]

        if Name.Outlines in root:
            report.removed("Outlines", "Catalog", "Removed bookmarks")
            del root[Name.Outlines]

        if Name.Names in root and Name.JavaScript in root[Name.Names]:
            report.removed("JavaScript", "Catalog", "Removed JS tree")
            del root[Name.Names][Name.JavaScript]

        for i, page in enumerate(pdf.pages):
            pid = f"Page {i}"

            if Name.AA in page:
                report.removed("PageAction", pid, "Removed")
                del page[Name.AA]

            if Name.OpenAction in page:
                report.removed("PageOpenAction", pid, "Removed")
                del page[Name.OpenAction]

            if Name.Annots in page:
                new_annots = []

                for annot in page[Name.Annots]:

                    if Name.A in annot:
                        report.removed("Action", pid, "Removed")
                        del annot[Name.A]

                    # 🔧 FIX: Remove direct URI links (prevents click-through)
                    if Name.URI in annot:
                        report.removed("URI", pid, "Removed direct URI")
                        del annot[Name.URI]

                    if Name.Dest in annot:
                        report.removed("Destination", pid, "Removed")
                        del annot[Name.Dest]

                    if Name.JS in annot:
                        report.removed("JavaScript", pid, "Removed")
                        del annot[Name.JS]

                    if Name.RichMediaContent in annot:
                        report.removed("RichMedia", pid, "Removed")
                        del annot[Name.RichMediaContent]

                    if annot.get(Name.Subtype) == Name.Link:
                        report.removed("Link", pid, "Dropped")
                        continue

                    new_annots.append(annot)

                if new_annots:
                    page[Name.Annots] = new_annots
                else:
                    del page[Name.Annots]

        pdf.save(output_pdf, linearize=True, compress_streams=True)

    final_risk = risk(report.total_score)

    db.execute("""
        UPDATE scans
        SET total_score=?, risk_level=?
        WHERE id=?
    """, (report.total_score, final_risk, scan_id))

    db.commit()
    return output_pdf


# ====================================================================
# ================= PPT / OLE / OOXML CDR EXTENSION ====================
# ADDITIVE ONLY — PDF LOGIC ABOVE IS UNTOUCHED
# ====================================================================

import zipfile
import shutil
import xml.etree.ElementTree as ET

OOXML_EXTENSIONS = (".ppt", ".pptx", ".docx", ".xlsx")

def sanitize_ppt_ooxml(input_file):
    db = get_db()

    sha256 = compute_sha256(input_file)
    if db.execute("SELECT 1 FROM scans WHERE sha256=?", (sha256,)).fetchone():
        return None

    output_file = os.path.join(
        OUTPUT_DIR,
        Path(input_file).stem + "_SANITIZED" + Path(input_file).suffix
    )

    cur = db.execute("""
        INSERT INTO scans
        (original_filename, sanitized_filename, input_path,
         output_path, total_score, sha256, risk_level)
        VALUES (?, ?, ?, ?, 0, ?, 'PENDING')
    """, (
        Path(input_file).name,
        Path(output_file).name,
        input_file,
        output_file,
        sha256
    ))

    scan_id = cur.lastrowid
    report = CDRReport(scan_id, db)

    report.found("OOXML Scan", "Container", "OOXML structure analyzed")

    raw_bytes = Path(input_file).read_bytes()
    urls, ips = extract_iocs_from_bytes(raw_bytes)
    domains = extract_domains(urls)

    for url in urls:
        report.found("External URL", "OOXML Binary", defang_url(url))

    for ip in ips:
        report.found("External IP", "OOXML Binary", ip)

    for d in domains:
        report.found("Domain", "OOXML Binary", d)

    temp_dir = Path(input_file).with_suffix("").as_posix() + "_tmp"
    os.makedirs(temp_dir, exist_ok=True)

    with zipfile.ZipFile(input_file, "r") as zin:
        zin.extractall(temp_dir)

    macro_found = False
    for root, _, files in os.walk(temp_dir):
        if "vbaproject.bin" in [f.lower() for f in files]:
            macro_found = True
            for f in files:
                if f.lower() == "vbaproject.bin":
                    report.removed("Macro", root, "Removed VBA macro")
                    os.remove(os.path.join(root, f))

    if not macro_found:
        report.found("Macro", "OOXML", "No VBA macros found")

    external_found = False
    for root, _, files in os.walk(temp_dir):
        for f in files:
            if f.endswith(".rels"):
                rels_path = os.path.join(root, f)
                tree = ET.parse(rels_path)
                rel_root = tree.getroot()

                removed = False
                for rel in list(rel_root):
                    target = rel.attrib.get("Target", "")
                    if target.startswith(("http", "https", "mailto", "ftp")) or rel.attrib.get("TargetMode") == "External":
                        report.removed("ExternalRelationship", rels_path, target)
                        rel_root.remove(rel)
                        removed = True
                        external_found = True

                if removed:
                    tree.write(rels_path, encoding="utf-8", xml_declaration=True)

    if not external_found:
        report.found("ExternalRelationship", "OOXML", "No external relationships found")

    ole_found = False
    for root, _, files in os.walk(temp_dir):
        for f in files:
            if f.lower().endswith(".bin"):
                ole_found = True

    if not ole_found:
        report.found("EmbeddedObject", "OOXML", "No embedded OLE objects found")

    shutil.make_archive(output_file.replace(Path(output_file).suffix, ""), 'zip', temp_dir)
    shutil.move(output_file.replace(Path(output_file).suffix, "") + ".zip", output_file)
    shutil.rmtree(temp_dir, ignore_errors=True)

    final_risk = risk(report.total_score)

    db.execute("""
        UPDATE scans
        SET total_score=?, risk_level=?
        WHERE id=?
    """, (report.total_score, final_risk, scan_id))

    db.commit()
    return output_file
