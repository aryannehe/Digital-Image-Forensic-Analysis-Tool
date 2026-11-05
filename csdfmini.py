import base64
import hashlib
import html
import io
import json
import math
import uuid
from datetime import datetime, timezone

import streamlit as st
from PIL import Image, ImageChops, ImageEnhance, ExifTags
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


# -------------------- Utility functions --------------------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_hashes(file_bytes: bytes) -> dict:
    return {
        "MD5": hashlib.md5(file_bytes).hexdigest(),
        "SHA1": hashlib.sha1(file_bytes).hexdigest(),
        "SHA256": sha256_hex(file_bytes),
    }


def extract_metadata(image: Image.Image) -> dict:
    metadata = {}
    try:
        exif = image.getexif()
        for tag, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag, str(tag))
            # Keep report/UI values readable and avoid very large nested values.
            metadata[tag_name] = str(value)[:300]
    except Exception as exc:
        metadata["Metadata extraction note"] = str(exc)
    return metadata or {"Info": "No EXIF metadata found."}


def image_entropy(image: Image.Image) -> float:
    gray = image.convert("L")
    hist = gray.histogram()
    total = sum(hist)
    if not total:
        return 0.0
    probs = [count / total for count in hist if count]
    return -sum(p * math.log2(p) for p in probs)


def ela_analysis(image: Image.Image):
    """Run a basic ELA visualization in memory; no temporary files are written."""
    rgb = image.convert("RGB")
    buffer = io.BytesIO()
    rgb.save(buffer, format="JPEG", quality=90)
    buffer.seek(0)
    with Image.open(buffer) as recompressed:
        recompressed.load()
        diff = ImageChops.difference(rgb, recompressed.convert("RGB"))
    extrema = diff.getextrema()
    max_diff = max(channel[1] for channel in extrema)
    scale = 255.0 / max_diff if max_diff else 1.0
    visual = ImageEnhance.Brightness(diff).enhance(scale)
    pixels = list(visual.convert("L").getdata())
    mean_diff = sum(pixels) / len(pixels) if pixels else 0.0
    return visual, mean_diff


def calculate_suspicion_level(entropy: float, ela_mean: float):
    # These are illustrative heuristics, not validated forensic thresholds.
    if entropy < 4.5 and ela_mean < 15:
        return "Low", "These simple indicators did not cross the configured thresholds."
    if (4.5 <= entropy < 6) or (15 <= ela_mean < 30):
        return "Medium", "One or more indicators fall in a configured intermediate range."
    return "High", "One or more indicators crossed the configured high range."


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key, private_pem, public_pem


def public_key_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_hex(der)


def sign_hash(private_key, digest_hex: str) -> bytes:
    # RSA-PSS signs the SHA-256 hex digest string, not the raw image.
    return private_key.sign(
        digest_hex.encode("ascii"),
        padding.PSS(mgf=padding.MGF1(crypto_hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        crypto_hashes.SHA256(),
    )


def verify_signature(public_key, digest_hex: str, signature: bytes) -> bool:
    public_key.verify(
        signature,
        digest_hex.encode("ascii"),
        padding.PSS(mgf=padding.MGF1(crypto_hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        crypto_hashes.SHA256(),
    )
    return True


def create_pdf_report(details: dict, original_image: Image.Image, ela_image: Image.Image) -> bytes:
    output = io.BytesIO()
    pdf = canvas.Canvas(output, pagesize=letter)
    page_w, page_h = letter
    left, y = 48, page_h - 48
    max_width = page_w - 96

    def ensure_space(required=24):
        nonlocal y
        if y < 65 + required:
            pdf.showPage()
            y = page_h - 48

    def heading(text):
        nonlocal y
        ensure_space(30)
        pdf.setFont("Helvetica-Bold", 13)
        pdf.drawString(left, y, text)
        y -= 20

    def line(text, font="Helvetica", size=9, indent=8):
        nonlocal y
        pdf.setFont(font, size)
        # Basic wrapping by character count for readable report lines.
        max_chars = 105 if size <= 9 else 88
        chunks = [text[i:i + max_chars] for i in range(0, len(text), max_chars)] or [""]
        for chunk in chunks:
            ensure_space(15)
            pdf.drawString(left + indent, y, chunk)
            y -= 13

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(left, y, "DIGITAL IMAGE FORENSIC INVESTIGATION REPORT")
    y -= 28
    line(f"Case ID: {details['case_id']}", size=10, indent=0)
    line(f"Report generated (UTC): {details['timestamp']}", size=9, indent=0)
    line(f"Evidence filename: {details['filename']}", size=9, indent=0)
    line(f"File size: {details['file_size']} bytes", size=9, indent=0)
    line(f"Image dimensions: {details['dimensions']}", size=9, indent=0)

    heading("1. Evidence Identification and Integrity")
    for name, value in details["hashes"].items():
        line(f"{name}: {value}")
    line("Interpretation: a hash is a file fingerprint. A later matching hash supports byte-for-byte integrity against a recorded baseline; it does not prove the image depicts a genuine event.")

    heading("2. Evidence Verification and Authentication")
    line(f"Evidence package provided: {'Yes' if details['package_present'] else 'No'}")
    line(f"Image hash matches signed hash: {details['hash_match']}")
    line(f"RSA signature verification: {details['signature_status']}")
    line(f"Public-key SHA-256 fingerprint: {details['key_fingerprint'] or 'Not available'}")
    line("RSA-PSS verifies that the signed hash matches the corresponding public key. Trust in the signer depends on how the public key is authenticated and protected.")

    heading("3. Image Properties and EXIF Metadata")
    line(f"Format: {details['format']}; mode: {details['mode']}")
    line(f"Entropy: {details['entropy']}")
    for key, value in list(details["metadata"].items())[:12]:
        line(f"{key}: {str(value)}")

    heading("4. ELA and Preliminary Suspicion Assessment")
    line(f"ELA mean grayscale difference: {details['ela_mean']}")
    line(f"Rule-based indicator level: {details['suspicion_level']}")
    line(f"Interpretation: {details['suspicion_explanation']}")
    line("Limitation: ELA and entropy are preliminary indicators only. They can produce false positives and false negatives and do not prove tampering.")

    # Add original and ELA pictures if space permits, preserving aspect ratio.
    ensure_space(210)
    heading("5. Original Image and ELA Visualization")
    y -= 2
    available_w, available_h = 245, 165
    for image, x in [(original_image, left), (ela_image, left + 265)]:
        img_buf = io.BytesIO()
        image.convert("RGB").save(img_buf, format="JPEG", quality=90)
        img_buf.seek(0)
        iw, ih = image.size
        scale = min(available_w / max(iw, 1), available_h / max(ih, 1))
        draw_w, draw_h = iw * scale, ih * scale
        pdf.drawImage(ImageReader(img_buf), x, y - draw_h, width=draw_w, height=draw_h,
                      preserveAspectRatio=True, mask="auto")
    y -= 180

    heading("6. Methodology and Limitations")
    line("Methods: SHA-256/MD5/SHA-1 hashing, EXIF extraction, grayscale histogram entropy, JPEG recompression ELA, and optional RSA-PSS signature verification.")
    line("This report is an automated preliminary examination. Preserve the original evidence, document acquisition circumstances, and use validated forensic procedures for formal investigations.")
    pdf.save()
    return output.getvalue()


# -------------------- Streamlit application --------------------
st.set_page_config(page_title="Digital Image Forensic Tool", layout="wide")

st.markdown(
    """
    <style>
    :root {
        --bg: #f6f3ec;
        --surface: #ffffff;
        --border: #d8d2c4;
        --text: #26302f;
        --muted: #6a726f;
        --primary: #1f6f6b;
        --primary-dark: #154f4c;
        --tint: #e6f0ee;
        color-scheme: light;
    }

    html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
        background-color: var(--bg) !important;
        color: var(--text) !important;
        font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    }
    header[data-testid="stHeader"] { background: var(--bg) !important; }
    .block-container { max-width: 1180px; padding-top: 2.5rem; padding-bottom: 3rem; }

    /* text */
    .stApp p, .stApp li, .stApp label, .stApp div[data-testid="stMarkdownContainer"] { color: var(--text); }
    [data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p,
    [data-testid="stImageCaption"] { color: var(--muted) !important; }
    h1 { font-size: 1.7rem; font-weight: 600; color: var(--primary-dark) !important; }
    h2, h3 {
        font-size: 1.05rem !important;
        font-weight: 600 !important;
        color: var(--primary-dark) !important;
        border-bottom: 2px solid var(--tint);
        padding-bottom: 0.35rem;
        margin-top: 2rem !important;
    }
    code { background: var(--tint) !important; color: var(--primary-dark) !important; }
    [data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] p, label { color: var(--text) !important; font-weight: 500; }

    /* text input */
    [data-baseweb="input"], [data-baseweb="base-input"] {
        background-color: var(--surface) !important;
        border: 1px solid var(--border) !important;
        border-radius: 4px !important;
    }
    [data-baseweb="input"] input {
        background-color: var(--surface) !important;
        color: var(--text) !important;
        -webkit-text-fill-color: var(--text) !important;
    }
    [data-baseweb="input"] input::placeholder { color: #9aa29f !important; -webkit-text-fill-color: #9aa29f !important; }
    [data-baseweb="input"]:focus-within { border-color: var(--primary) !important; }

    /* all buttons: teal outline, teal text; hover fills tint */
    button[data-testid^="stBaseButton"] {
        background: var(--surface) !important;
        border: 1px solid var(--primary) !important;
        border-radius: 4px !important;
        box-shadow: none !important;
    }
    button[data-testid^="stBaseButton"],
    button[data-testid^="stBaseButton"] * { color: var(--primary-dark) !important; font-weight: 500; }
    button[data-testid^="stBaseButton"]:hover { background: var(--tint) !important; }

    /* primary + upload buttons: solid teal, white text */
    button[data-testid="stBaseButton-primary"],
    [data-testid="stFileUploaderDropzone"] button {
        background: var(--primary) !important;
        border-color: var(--primary) !important;
    }
    button[data-testid="stBaseButton-primary"],
    button[data-testid="stBaseButton-primary"] *,
    [data-testid="stFileUploaderDropzone"] button,
    [data-testid="stFileUploaderDropzone"] button * { color: #ffffff !important; }
    button[data-testid="stBaseButton-primary"]:hover,
    [data-testid="stFileUploaderDropzone"] button:hover { background: var(--primary-dark) !important; }

    /* file uploader */
    [data-testid="stFileUploaderDropzone"] {
        background: var(--surface) !important;
        border: 1px dashed #b5ada0 !important;
        border-radius: 4px;
    }
    [data-testid="stFileUploaderDropzone"] span,
    [data-testid="stFileUploaderDropzone"] small { color: var(--muted) !important; }
    [data-testid="stFileUploaderFile"] * { color: var(--text) !important; }

    /* metrics */
    [data-testid="stMetric"] {
        background: var(--surface);
        border: 1px solid var(--border);
        border-left: 4px solid var(--primary);
        border-radius: 4px;
        padding: 0.7rem 0.9rem;
    }
    [data-testid="stMetricLabel"] p { font-size: 0.8rem; color: var(--muted) !important; }
    [data-testid="stMetricValue"] { font-size: 1.15rem; font-weight: 600; color: var(--text) !important; }

    /* JSON blocks */
    pre.jsonbox {
        background: var(--tint);
        color: var(--primary-dark);
        border: 1px solid #c9dcd8;
        border-radius: 4px;
        padding: 0.8rem 1rem;
        font-family: Consolas, "Courier New", monospace;
        font-size: 0.85rem;
        line-height: 1.5;
        white-space: pre-wrap;
        word-break: break-all;
        margin: 0;
    }

    /* alerts */
    [data-testid="stAlert"] { border-radius: 4px; border: 1px solid var(--border); }
    [data-testid="stAlert"] p { color: var(--text) !important; }
    div[data-testid="stAlertContainer"]:has([data-testid="stAlertContentInfo"]) { background: var(--tint); }
    div[data-testid="stAlertContainer"]:has([data-testid="stAlertContentSuccess"]) { background: #e3efe4; }
    div[data-testid="stAlertContainer"]:has([data-testid="stAlertContentError"]) { background: #f4e2df; }

    /* header bar */
    .appbar {
        background: var(--primary-dark);
        padding: 1.4rem 1.6rem;
        border-radius: 4px;
        margin-bottom: 1.5rem;
    }
    .appbar h1 { color: #ffffff !important; margin: 0; padding: 0; font-size: 1.5rem; }
    .appbar p { color: #cfe3e0 !important; margin: 0.3rem 0 0 0; font-size: 0.9rem; }

    /* tabs */
    button[data-baseweb="tab"] { background: transparent !important; }
    button[data-baseweb="tab"] p { color: var(--muted) !important; font-weight: 500; }
    button[data-baseweb="tab"][aria-selected="true"] p { color: var(--primary-dark) !important; }
    [data-baseweb="tab-highlight"] { background-color: var(--primary) !important; }
    [data-baseweb="tab-border"] { background-color: var(--border) !important; }
    div[data-baseweb="tab-panel"] { padding-top: 1.2rem; }
    h3 { margin-top: 0.5rem !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


def show_json(data):
    st.markdown(
        f'<pre class="jsonbox">{html.escape(json.dumps(data, indent=2))}</pre>',
        unsafe_allow_html=True,
    )

st.markdown(
    """
    <div class="appbar">
        <h1>Digital Image Forensic Analysis Tool</h1>
        <p>Image integrity, RSA digital signatures, preliminary manipulation indicators and reporting.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Session-scoped key pair. Download and securely retain the private key if signatures must remain verifiable later.
if "rsa_keys" not in st.session_state:
    st.session_state.rsa_keys = generate_rsa_keypair()

private_key, public_key, private_pem, public_pem = st.session_state.rsa_keys

in_left, in_right = st.columns([2, 1])
with in_left:
    uploaded_file = st.file_uploader("Upload an image for examination", type=["jpg", "jpeg", "png", "tif", "tiff", "webp"])
with in_right:
    case_id_input = st.text_input("Case ID (optional)", placeholder="e.g. CASE-2026-001")

if uploaded_file:
    file_bytes = uploaded_file.getvalue()
    try:
        with Image.open(io.BytesIO(file_bytes)) as opened:
            opened.verify()
        img = Image.open(io.BytesIO(file_bytes))
        img.load()
    except Exception as exc:
        st.error(f"The uploaded file could not be decoded as a valid image: {exc}")
        st.stop()

    if img.width * img.height > 40_000_000:
        st.error("Image exceeds the 40-megapixel safety limit. Please use a smaller image.")
        st.stop()

    hashes = get_hashes(file_bytes)
    entropy_val = round(image_entropy(img), 3)
    metadata = extract_metadata(img)
    ela_img, ela_mean_raw = ela_analysis(img)
    ela_mean = round(ela_mean_raw, 3)
    suspicion_level, suspicion_explanation = calculate_suspicion_level(entropy_val, ela_mean)
    case_id = case_id_input.strip() or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    key_fingerprint = public_key_fingerprint(public_key)

    # Summary row
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("File size", f"{len(file_bytes):,} bytes")
    m2.metric("Dimensions", f"{img.width} × {img.height}")
    m3.metric("Entropy", f"{entropy_val:.3f}")
    m4.metric("Format / color mode", f"{img.format or 'Unknown'} / {img.mode}")
    st.write(f"**Case ID:** {case_id}")

    tab_evidence, tab_signature, tab_analysis, tab_report = st.tabs(
        ["Evidence", "Signature & Verification", "Analysis", "Report"]
    )

    # ---------------- Evidence ----------------
    with tab_evidence:
        ev_left, ev_right = st.columns([3, 2])
        with ev_left:
            st.subheader("Evidence Image")
            st.image(img, caption=f"Evidence image: {uploaded_file.name}", use_container_width=True)
        with ev_right:
            st.subheader("File Integrity Hashes")
            show_json(hashes)

    # ---------------- Signature & Verification ----------------
    package_present = False
    hash_match = "Not checked"
    signature_status = "Not checked"
    verification_message = "Upload a signed evidence package to verify this image."
    verification_key_fingerprint = ""

    with tab_signature:
        sig_left, sig_right = st.columns(2, gap="large")

        with sig_left:
            st.subheader("RSA Digital Signature")
            st.write(
                "Sign the SHA-256 digest of the current image using RSA-PSS. "
                "The resulting evidence package can be used later to verify the same image."
            )
            if st.button("Sign image evidence with RSA", type="primary"):
                signature = sign_hash(private_key, hashes["SHA256"])
                package = {
                    "schema": "digital-image-forensic-evidence-v1",
                    "case_id": case_id,
                    "filename": uploaded_file.name,
                    "signed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "hash_algorithm": "SHA-256",
                    "sha256": hashes["SHA256"],
                    "signature_algorithm": "RSA-PSS-SHA256",
                    "signature_base64": base64.b64encode(signature).decode("ascii"),
                    "public_key_pem": public_pem.decode("ascii"),
                    "public_key_sha256_fingerprint": key_fingerprint,
                }
                st.session_state.signed_package = package
                st.success("Evidence hash signed. Download the evidence package and preserve it with the original file.")

            signed_package = st.session_state.get("signed_package")
            if signed_package:
                st.download_button(
                    "Download signed evidence package (JSON)",
                    data=json.dumps(signed_package, indent=2).encode("utf-8"),
                    file_name=f"{case_id}_signed_evidence.json",
                    mime="application/json",
                )
                st.caption(f"Signed SHA-256: {signed_package['sha256']}")

        with sig_right:
            st.subheader("Verify Evidence and Authenticate Signature")
            package_file = st.file_uploader(
                "Upload a previously downloaded signed evidence package (JSON)",
                type=["json"],
                key="verification_package",
            )

            if package_file:
                package_present = True
                try:
                    package = json.loads(package_file.getvalue().decode("utf-8"))
                    recorded_hash = str(package["sha256"])
                    signature = base64.b64decode(package["signature_base64"], validate=True)
                    package_public_pem = package["public_key_pem"].encode("ascii")
                    verification_public_key = serialization.load_pem_public_key(package_public_pem)
                    verification_key_fingerprint = public_key_fingerprint(verification_public_key)

                    hash_matches = hashes["SHA256"].lower() == recorded_hash.lower()
                    hash_match = "MATCH" if hash_matches else "MISMATCH"
                    try:
                        verify_signature(verification_public_key, recorded_hash, signature)
                        signature_valid = True
                    except InvalidSignature:
                        signature_valid = False

                    if signature_valid and hash_matches:
                        signature_status = "VALID"
                        verification_message = "The uploaded image hash matches the signed hash and the RSA signature is valid for the supplied public key."
                        st.success(verification_message)
                    elif not hash_matches and signature_valid:
                        signature_status = "VALID for recorded hash; uploaded image differs"
                        verification_message = "The signature is valid for the package's recorded hash, but the uploaded image does not match that hash."
                        st.error(verification_message)
                    else:
                        signature_status = "INVALID"
                        verification_message = "The RSA signature did not verify. The package may be altered, corrupt, or paired with the wrong public key."
                        st.error(verification_message)

                    st.write(f"**Image hash comparison:** {hash_match}")
                    st.write(f"**RSA signature status:** {signature_status}")
                    st.write(f"**Package case ID:** {package.get('case_id', 'Not specified')}")
                    st.write(f"**Public-key fingerprint:** `{verification_key_fingerprint}`")
                    st.caption("This verifies the signature against the public key embedded in the package. Independently authenticate that public key to establish the signer's identity.")
                except Exception as exc:
                    signature_status = "ERROR"
                    verification_message = f"Could not verify this evidence package: {exc}"
                    st.error(verification_message)

    # ---------------- Analysis ----------------
    with tab_analysis:
        st.subheader("ELA Analysis")
        col1, col2 = st.columns(2)
        with col1:
            st.image(img, caption="Original image", use_container_width=True)
        with col2:
            st.image(ela_img, caption="ELA visualization (bright areas are not proof of tampering)", use_container_width=True)
        st.write(f"**ELA mean grayscale difference:** {ela_mean}")

        an_left, an_right = st.columns(2, gap="large")
        with an_left:
            st.subheader("Preliminary Suspicion Assessment")
            st.write(f"**Indicator level: {suspicion_level}**")
            st.write(suspicion_explanation)
            st.info(
                "This rule-based score is a preliminary indicator, not a forensic conclusion. "
                "Entropy and ELA thresholds must be validated against known genuine and manipulated images."
            )
        with an_right:
            st.subheader("EXIF Metadata")
            show_json(metadata)

    # ---------------- Report ----------------
    details = {
        "case_id": case_id,
        "timestamp": timestamp,
        "filename": uploaded_file.name,
        "file_size": len(file_bytes),
        "dimensions": f"{img.width} x {img.height}",
        "format": img.format or "Unknown",
        "mode": img.mode,
        "hashes": hashes,
        "entropy": entropy_val,
        "metadata": metadata,
        "ela_mean": ela_mean,
        "suspicion_level": suspicion_level,
        "suspicion_explanation": suspicion_explanation,
        "package_present": package_present,
        "hash_match": hash_match,
        "signature_status": signature_status,
        "key_fingerprint": verification_key_fingerprint or key_fingerprint,
    }
    pdf_bytes = create_pdf_report(details, img, ela_img)
    with tab_report:
        st.subheader("Investigation and Evidence Report")
        st.write("The report includes case details, hashes, RSA verification status, metadata, ELA results, findings and limitations.")
        st.download_button(
            "Download Investigation & Evidence Report (PDF)",
            data=pdf_bytes,
            file_name=f"{case_id}_forensic_report.pdf",
            mime="application/pdf",
        )
else:
    st.info("Upload an image to begin the forensic examination.")
    st.markdown(
        """
        **Included modules**
        - File hashing (MD5, SHA-1, SHA-256)
        - EXIF metadata and image entropy
        - Error Level Analysis (ELA)
        - RSA-PSS digital signatures for evidence hashes
        - Evidence verification and authentication
        - Downloadable signed evidence package (JSON)
        - Investigation and evidence report (PDF)
        """
    )