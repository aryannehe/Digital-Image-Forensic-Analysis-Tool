# Digital Image Forensic Analysis Tool

A Python-based digital forensics application that combines image manipulation analysis, cryptographic integrity verification, and digital evidence authentication to examine the authenticity and reliability of digital images.

## Overview

The **Digital Image Forensic Analysis Tool** is an interactive web application designed to investigate potential image manipulation and maintain the integrity of digital evidence.

The application integrates multiple forensic and cryptographic techniques, including Error Level Analysis (ELA), Shannon Entropy, EXIF metadata extraction, MD5, SHA-1, SHA-256 hashing, and RSA digital signatures.

It analyses image characteristics, identifies potential inconsistencies, generates cryptographically signed evidence packages, and verifies previously recorded evidence. The application also generates structured PDF investigation reports containing forensic findings and verification results.

## Key Features

- **Multi-Algorithm Hashing:** Generates MD5, SHA-1, and SHA-256 fingerprints for uploaded image files.
- **EXIF Metadata Analysis:** Extracts embedded image metadata to examine available information about image properties and provenance.
- **Error Level Analysis (ELA):** Performs JPEG recompression analysis to highlight variations in compression error levels.
- **Shannon Entropy Calculation:** Analyses grayscale pixel intensity distributions to measure image information complexity.
- **Preliminary Tampering Assessment:** Combines entropy and ELA measurements to generate Low, Medium, or High suspicion indicators.
- **RSA Digital Signatures:** Implements RSA-2048 with RSA-PSS and SHA-256 for cryptographic signing of image hashes.
- **Evidence Authentication:** Validates digital signatures and compares uploaded image hashes against previously signed evidence.
- **Signed Evidence Packages:** Exports cryptographic evidence records in JSON format.
- **Automated PDF Reports:** Generates downloadable investigation reports with forensic findings, image properties, and authentication results.
- **Interactive Dashboard:** Provides an integrated Streamlit interface for image examination and evidence management.

## Core Algorithms & Technical Implementation

The project integrates image-processing algorithms, statistical analysis, and cryptographic mechanisms into a unified forensic workflow.

### 1. Cryptographic Hashing and File Integrity

The application implements three hashing algorithms using Python's `hashlib` library:

- **MD5:** Generates a 128-bit digest for file identification and compatibility with legacy forensic records.
- **SHA-1:** Generates a 160-bit digest for additional file fingerprinting.
- **SHA-256:** Generates a 256-bit cryptographic digest used as the primary integrity reference and input for digital signature generation.

All hashes are calculated directly from the original uploaded file bytes rather than a processed or converted image. This ensures that the fingerprints represent the actual evidence file.

A change in the file content produces a different digest, allowing the application to identify modifications when compared against a previously recorded hash.

### 2. Error Level Analysis (ELA)

The application implements ELA using the Pillow image-processing library to examine differences introduced during JPEG recompression.

The implementation follows this process:

1. Converts the uploaded image into RGB format.
2. Recompresses the image into JPEG format at a fixed quality level of 90.
3. Calculates the pixel-wise difference between the original and recompressed images using `ImageChops.difference()`.
4. Normalizes the difference image using brightness enhancement to make variations more visible.
5. Calculates the mean grayscale difference as a numerical ELA indicator.

The resulting visualization highlights regions with varying compression error levels, helping investigators identify areas that may require further examination.

### 3. Shannon Entropy Analysis

The application calculates grayscale image entropy using the Shannon entropy formula.

First, the uploaded image is converted into grayscale, and its pixel intensity histogram is generated. The frequency of each intensity level is then converted into a probability distribution.

The entropy is calculated as:

\[
H(X)=-\sum_{i=1}^{n}p_i\log_2(p_i)
\]

Where:

- \(p_i\) represents the probability of a particular grayscale intensity.
- \(H(X)\) represents the overall image entropy.

The calculated entropy provides a statistical measure of the complexity and distribution of image intensities. It is used alongside ELA measurements as a supporting indicator during forensic examination.

### 4. EXIF Metadata Extraction

The application uses Pillow's EXIF interface and `ExifTags` mappings to retrieve embedded metadata from uploaded images.

The extraction process identifies available metadata tags and maps their numerical identifiers to readable names.

Depending on the source image, the extracted information may include:

- Camera manufacturer and model.
- Date and time information.
- Image orientation.
- Exposure and camera settings.
- Other embedded image properties.

The extracted metadata is presented in a structured JSON-style format to assist in examining image properties and potential inconsistencies.

### 5. RSA Digital Signatures and Evidence Authentication

The application implements public-key cryptography using the Python `cryptography` library.

It generates a **2048-bit RSA key pair** using public exponent 65537 and implements RSA-PSS with MGF1-SHA256 for digital signature operations.

The evidence authentication workflow consists of:

1. Calculating the SHA-256 digest of the original image.
2. Signing the hexadecimal SHA-256 digest using the RSA private key.
3. Encoding the resulting signature using Base64.
4. Exporting the signature, public key, image hash, case ID, timestamp, and public-key fingerprint into a JSON evidence package.
5. Recomputing the image hash during subsequent verification.
6. Comparing the recomputed digest against the recorded digest.
7. Verifying the RSA-PSS signature using the public key included in the evidence package.

The application independently evaluates the hash comparison and digital signature verification, allowing it to distinguish between an altered image, an invalid signature, and successfully authenticated evidence.

### 6. Rule-Based Forensic Assessment

The application combines the numerical results obtained from ELA and entropy analysis to produce a preliminary suspicion indicator.

The implemented assessment uses configurable threshold-based conditions:

| Indicator | Assessment |
|---|---|
| Low | Entropy below 4.5 and ELA mean below 15 |
| Medium | Entropy between 4.5–6 or ELA mean between 15–30 |
| High | Values crossing the configured high-range thresholds |

The resulting classification provides an initial indication of potential inconsistencies and helps organize further investigation.

These thresholds are illustrative heuristics and are not validated forensic detection standards. The classification should not be interpreted as definitive proof of image manipulation.

## Technology Stack

| Technology | Implementation |
|---|---|
| Python | Core application logic and forensic algorithms |
| Streamlit | Interactive web application |
| Pillow (PIL) | Image processing, EXIF extraction, and ELA |
| Hashlib | MD5, SHA-1, and SHA-256 hashing |
| Cryptography | RSA-2048, RSA-PSS, MGF1, and signature verification |
| ReportLab | Automated PDF investigation reports |
| Math | Shannon entropy calculation |
| Base64 | Digital signature encoding |
| JSON | Structured signed evidence packages |

## Application Workflow

```text
             IMAGE UPLOAD
                   |
                   v
           IMAGE VALIDATION
                   |
                   v
          EVIDENCE IDENTIFICATION
                   |
          +--------+---------+
          |                  |
          v                  v
     HASH GENERATION    IMAGE ANALYSIS
          |                  |
     MD5 / SHA-1       EXIF EXTRACTION
     SHA-256           ENTROPY ANALYSIS
          |             ELA ANALYSIS
          |                  |
          |                  v
          |          SUSPICION ASSESSMENT
          |                  |
          +--------+---------+
                   |
                   v
          RSA DIGITAL SIGNING
                   |
                   v
          SIGNED JSON PACKAGE
                   |
                   v
          EVIDENCE VERIFICATION
                   |
                   v
          PDF REPORT GENERATION
```

## Installation and Setup

### Prerequisites

- Python 3.9 or later
- pip (Python package manager)
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/your-repository.git
```

### 2. Navigate to the Project Directory

```bash
cd your-repository
```

### 3. Install Dependencies

```bash
pip install streamlit pillow cryptography reportlab
```

### 4. Run the Application

```bash
streamlit run csdfmini.py
```

### 5. Access the Application

Open the local URL displayed in your terminal:

```text
http://localhost:8501
```

## Evidence Verification Outcomes

During evidence verification, the application performs two independent checks: SHA-256 hash comparison and RSA-PSS signature verification.

| Hash Comparison | Signature Verification | Result |
|---|---|---|
| MATCH | VALID | Evidence successfully verified |
| MISMATCH | VALID | Signed package is valid, but the uploaded image differs |
| MATCH / MISMATCH | INVALID | Digital signature verification failed |

This separation helps distinguish image integrity issues from signature authentication failures.

## Generated Investigation Reports

The application generates downloadable PDF reports containing:

- Case ID and evidence identification details.
- File size, image dimensions, and format.
- MD5, SHA-1, and SHA-256 hash values.
- RSA signature verification status.
- Public-key SHA-256 fingerprint.
- Extracted EXIF metadata.
- Image entropy measurements.
- ELA visualization and numerical results.
- Preliminary suspicion assessment.
- Methodology and forensic limitations.

## Supported Image Formats

- JPEG / JPG
- PNG
- TIFF
- WebP

**Image size restriction:** Files exceeding 40 megapixels are rejected to prevent excessive memory and processing consumption.

## Limitations and Security Considerations

- ELA and entropy are supporting forensic indicators and cannot independently establish image manipulation.
- The rule-based suspicion thresholds are illustrative and require validation against representative datasets.
- EXIF metadata can be modified, removed, or unavailable.
- MD5 and SHA-1 are retained for compatibility and identification; SHA-256 is used for cryptographic evidence signing.
- RSA signature verification establishes validity against the supplied public key but does not independently establish the identity of its owner.
- RSA keys are generated per application session. The private key is not persisted, so long-term signing workflows require appropriate secure key management.
- The application is intended for preliminary forensic examination rather than conclusive forensic certification.

## Future Enhancements

- Machine learning-based image manipulation detection.
- Copy-move and splicing forgery detection.
- Advanced noise and compression inconsistency analysis.
- Persistent and secure RSA key management.
- Evidence history and case management.
- Enhanced forensic visualization and investigation analytics.

## Contributors

Developed as a mini-project for the **Cyber Security and Data Forensics** course.

**Department of Computer Engineering**  
P.E.S. Modern College of Engineering, Pune  
Savitribai Phule Pune University

## License

This project is developed for academic and educational purposes. You may modify and extend it with appropriate attribution.

---

**Disclaimer:** This application provides preliminary image forensic indicators and cryptographic evidence verification. Its automated findings should not be treated as conclusive proof of image manipulation or as a substitute for validated forensic investigation procedures.
