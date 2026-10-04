const imageInput = document.getElementById("imageInput");
const originalCanvas = document.getElementById("originalCanvas");
const analysisCanvas = document.getElementById("analysisCanvas");
const extractedTextArea = document.getElementById("extractedText");

const channelSelect = document.getElementById("channelSelect");
const bitSelect = document.getElementById("bitSelect");
const renderPlaneBtn = document.getElementById("renderPlaneBtn");
const telemetryTitle = document.getElementById("telemetryTitle");

const secretInput = document.getElementById("secretInput");
const injectBtn = document.getElementById("injectBtn");

const origCtx = originalCanvas.getContext("2d", { willReadFrequently: true });
const analCtx = analysisCanvas.getContext("2d", { willReadFrequently: true });

let currentImageData = null;

// 1. FILE UPLOAD HANDLER
imageInput.addEventListener("change", function (e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (event) {
    const img = new Image();
    img.onload = function () {
      originalCanvas.width = img.width;
      originalCanvas.height = img.height;
      analysisCanvas.width = img.width;
      analysisCanvas.height = img.height;

      origCtx.drawImage(img, 0, 0);
      currentImageData = origCtx.getImageData(0, 0, img.width, img.height);

      // Default triage: Red channel, Bit 0 (LSB)
      renderBitPlane(0, 0);
      runForensicTriage();
    };
    img.src = event.target.result;
  };
  reader.readAsDataURL(file);
});

// 2. ARBITRARY BIT-PLANE RENDERER (0 to 7 across R, G, B)
function renderBitPlane(channelIdx, bitIdx) {
  if (!currentImageData) return;

  const w = originalCanvas.width;
  const h = originalCanvas.height;
  const px = currentImageData.data;

  const visualData = analCtx.createImageData(w, h);
  const vPx = visualData.data;

  const channelNames = ["Red", "Green", "Blue"];
  telemetryTitle.innerText = `Bit-Plane Telemetry (${channelNames[channelIdx]} - Bit ${bitIdx})`;

  for (let i = 0; i < px.length; i += 4) {
    const channelVal = px[i + channelIdx];
    // Shift target bit to index 0 and mask with 1
    const bit = (channelVal >> bitIdx) & 1;
    const intensity = bit === 1 ? 255 : 0;

    vPx[i] = intensity;     // R
    vPx[i + 1] = intensity; // G
    vPx[i + 2] = intensity; // B
    vPx[i + 3] = 255;       // A (fully opaque)
  }

  analCtx.putImageData(visualData, 0, 0);
}

renderPlaneBtn.addEventListener("click", function () {
  const channel = parseInt(channelSelect.value, 10);
  const bit = parseInt(bitSelect.value, 10);
  renderBitPlane(channel, bit);
});

// 3. FORENSIC TRIAGE & SIGNATURE CARVER
function runForensicTriage() {
  if (!currentImageData) return;
  const px = currentImageData.data;

  // Harvest sequential bits from Red channel LSB (Bit 0)
  const rawBytes = [];
  const maxBytes = Math.min(Math.floor(px.length / 32), 4096); // Analyze initial 4KB offset

  for (let i = 0; i < maxBytes * 32; i += 32) {
    let byteVal = 0;
    for (let b = 0; b < 8; b++) {
      const bit = px[i + b * 4] & 1;
      byteVal = (byteVal << 1) | bit;
    }
    rawBytes.push(byteVal);
  }

  // Check for Magic Numbers / File Signatures
  const signatureHit = detectMagicBytes(rawBytes);

  // Check for printable ASCII string payload
  let asciiStr = "";
  for (let b of rawBytes) {
    if (b === 0) break; // Null terminator
    asciiStr += String.fromCharCode(b);
  }

  let report = "=== STEGOSCAN FORENSIC REPORT ===\n";
  report += `Analyzed Dimensions: ${originalCanvas.width} x ${originalCanvas.height} px\n`;
  report += `Carrier Type: Lossless Raster Bitmap (Raw 24-bit RGB Data)\n\n`;

  if (signatureHit) {
    report += `[🚨] CRITICAL ARTIFACT: EMBEDDED FILE HEADER DETECTED!\n`;
    report += `Identified File Type : ${signatureHit.type}\n`;
    report += `File Magic Signature: ${signatureHit.magic}\n`;
    report += `Offset Header        : 0x00000000 (R-LSB Sequence)\n`;
    extractedTextArea.style.color = "#f85149";
  } else if (asciiStr.startsWith("FLAG{") || asciiStr.startsWith("STEGO:")) {
    report += `[🚨] CRITICAL ARTIFACT: CONFIRMED STEGANOGRAPHIC PAYLOAD!\n\n`;
    report += `Recovered String:\n${asciiStr}\n`;
    extractedTextArea.style.color = "#58a6ff";
  } else if (/^[ -~]{5,}$/.test(asciiStr)) {
    report += `[⚠️] ANOMALY DETECTED: SUSPICIOUS STRUCTURED STRING RECOVERED:\n\n`;
    report += `Recovered String:\n${asciiStr}\n`;
    extractedTextArea.style.color = "#e3b341";
  } else {
    report += `[+] ANALYSIS STATUS: CLEAN BASELINE\n`;
    report += `No known magic file signatures or structured ASCII strings detected in initial LSB offsets.\n`;
    report += `Random bit distribution consistent with natural sensor noise.\n`;
    extractedTextArea.style.color = "#3fb950";
  }

  extractedTextArea.value = report;
}

// Magic bytes lookup table
function detectMagicBytes(bytes) {
  if (bytes.length < 4) return null;

  // ZIP Archive: 50 4B 03 04
  if (bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04) {
    return { type: "ZIP Archive / OpenXML Package", magic: "50 4B 03 04 (PK..)" };
  }
  // PDF Document: 25 50 44 46 (%PDF)
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
    return { type: "PDF Document", magic: "25 50 44 46 (%PDF)" };
  }
  // PNG Image: 89 50 4E 47
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    return { type: "PNG Image", magic: "89 50 4E 47 (.PNG)" };
  }

  return null;
}

// 4. TEST ARTIFACT INJECTOR (RED CHANNEL BIT 0)
injectBtn.addEventListener("click", function () {
  const secretText = secretInput.value.trim();
  if (!secretText || !currentImageData) {
    alert("Please upload a base image and enter a test string first.");
    return;
  }

  const payload = "FLAG{" + secretText + "}";
  const px = currentImageData.data;

  // String to bits + 8 trailing zero bits (null terminator)
  let bits = [];
  for (let i = 0; i < payload.length; i++) {
    const code = payload.charCodeAt(i);
    for (let b = 7; b >= 0; b--) {
      bits.push((code >> b) & 1);
    }
  }
  for (let b = 0; b < 8; b++) bits.push(0);

  if (bits.length > px.length / 4) {
    alert("Payload exceeds carrier capacity.");
    return;
  }

  // Inject into Red Channel LSB
  for (let i = 0; i < bits.length; i++) {
    const pixelIndex = i * 4;
    px[pixelIndex] = (px[pixelIndex] & ~1) | bits[i];
  }

  origCtx.putImageData(currentImageData, 0, 0);

  // Re-run bit-plane rendering and forensic triage immediately
  renderBitPlane(parseInt(channelSelect.value, 10), parseInt(bitSelect.value, 10));
  runForensicTriage();

  // Export clean PNG
  const link = document.createElement("a");
  link.download = "stego_evidence.png";
  link.href = originalCanvas.toDataURL("image/png");
  link.click();
});