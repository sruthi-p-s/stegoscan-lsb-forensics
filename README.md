# StegoScan: LSB Forensic Workbench

A lightweight, client-side digital forensics investigation tool designed to analyze lossless digital images, isolate Least Significant Bit (LSB) planes, and detect hidden steganographic payloads.

## Overview
Covert data exfiltration often leverages spatial image steganography by replacing the lowest-order bit of color channels. Because a 1-unit variation in pixel luminance is imperceptible to the human eye, traditional inspections fail. StegoScan accesses raw pixel arrays via HTML5 Canvas to perform instant bitwise forensic analysis directly in the browser.

## Key Forensic Features
- **Bit-Plane Telemetry:** Isolates the zero-order bit of color channels and amplifies it to full scale (0 vs 255) to expose unnatural spatial patterns, hidden watermarks, or altered regions.
- **Sequential Payload Recovery:** Harvests trailing bits from pixel channels, groups them into 8-bit bytes, and checks for structured ASCII strings and standard flag formats (`FLAG{...}`).
- **Test Artifact Generator:** Embeds custom test strings into lossless carriers to generate ground-truth evidence samples for forensic verification.
- **Client-Side Execution:** Runs 100% in the browser with zero server dependency, eliminating cold starts and hosting downtime.

## Tech Stack
- **HTML5 Canvas** (Pixel manipulation & rendering)
- **JavaScript (Vanilla)** (Bitwise logic, FileReader API)
- **CSS3** (SOC Dark Mode UI)

## Supported File Formats
- Lossless formats only: `.png`, `.bmp`
- *(Note: Lossy formats like JPEG are unsupported because Discrete Cosine Transform [DCT] and quantization corrupt spatial LSB integrity).*

## Usage
1. Open the live deployment link.
2. Upload a suspect image via **Choose File**.
3. Inspect the **LSB Bit-Plane Telemetry** panel for structural anomalies.
4. Review extracted ASCII artifacts in the forensic output terminal.
