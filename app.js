const imageInput = document.getElementById("imageInput");
const originalCanvas = document.getElementById("originalCanvas");
const analysisCanvas = document.getElementById("analysisCanvas");
const extractedTextArea = document.getElementById("extractedText");

const secretInput = document.getElementById("secretInput");
const injectBtn = document.getElementById("injectBtn");

const origCtx = originalCanvas.getContext("2d", { willReadFrequently: true });
const analCtx = analysisCanvas.getContext("2d", { willReadFrequently: true });

let loadedImage = null;

// 1. FILE UPLOAD HANDLER
imageInput.addEventListener("change", function (e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (event) {
    const img = new Image();
    img.onload = function () {
      loadedImage = img;

      originalCanvas.width = img.width;
      originalCanvas.height = img.height;
      analysisCanvas.width = img.width;
      analysisCanvas.height = img.height;

      origCtx.drawImage(img, 0, 0);
      runForensicAnalysis();
    };
    img.src = event.target.result;
  };
  reader.readAsDataURL(file);
});

// 2. CORE LSB EXTRACTION ENGINE
function runForensicAnalysis() {
  const w = originalCanvas.width;
  const h = originalCanvas.height;
  if (w === 0 || h === 0) return;

  const imgData = origCtx.getImageData(0, 0, w, h);
  const px = imgData.data;

  // Bit-Plane Visualization (amplifying bit 0 of red channel)
  const visualData = analCtx.createImageData(w, h);
  const vPx = visualData.data;

  for (let i = 0; i < px.length; i += 4) {
    const bit = px[i] & 1;
    const val = bit === 1 ? 255 : 0;
    vPx[i] = val;
    vPx[i + 1] = val;
    vPx[i + 2] = val;
    vPx[i + 3] = 255;
  }
  analCtx.putImageData(visualData, 0, 0);

  // Extract raw sequential bits from Red channel only (standard LSB sequential mode)
  let bits = [];
  const maxBitsToRead = Math.min(px.length / 4, 32000); // Read up to 4000 characters

  for (let i = 0; i < maxBitsToRead * 4; i += 4) {
    bits.push(px[i] & 1);
  }

  // Convert bits to characters
  let recoveredText = "";
  for (let i = 0; i < bits.length; i += 8) {
    let byteVal = 0;
    for (let b = 0; b < 8; b++) {
      byteVal = (byteVal << 1) | bits[i + b];
    }
    if (byteVal === 0) break; // null terminator
    recoveredText += String.fromCharCode(byteVal);
  }

  // Evaluate findings
  if (recoveredText.startsWith("FLAG{") || recoveredText.startsWith("STEGO:")) {
    extractedTextArea.value = `[!] FORENSIC HIT: Confirmed LSB Steganographic Payload Detected!\n\nExtracted Payload:\n${recoveredText}`;
    extractedTextArea.style.color = "#58a6ff";
  } else if (/^[ -~]{5,}$/.test(recoveredText)) {
    extractedTextArea.value = `[!] FORENSIC HIT: Structured ASCII String Recovered:\n\n${recoveredText}`;
    extractedTextArea.style.color = "#e3b341";
  } else {
    extractedTextArea.value = "[+] Analysis Complete: Normal baseline image. No structured LSB steganographic payload detected.";
    extractedTextArea.style.color = "#3fb950";
  }
}

// 3. INJECTION ENGINE (Sequential Red-Channel LSB)
injectBtn.addEventListener("click", function () {
  const secretText = secretInput.value.trim();
  if (!secretText) {
    alert("Please enter a secret message first.");
    return;
  }

  if (originalCanvas.width === 0 || originalCanvas.height === 0) {
    alert("Please upload an image first.");
    return;
  }

  const payload = "FLAG{" + secretText + "}";

  // Convert string to bits + null terminator
  let bits = [];
  for (let i = 0; i < payload.length; i++) {
    const code = payload.charCodeAt(i);
    for (let b = 7; b >= 0; b--) {
      bits.push((code >> b) & 1);
    }
  }
  for (let b = 0; b < 8; b++) bits.push(0); // 8-bit null terminator

  const imgData = origCtx.getImageData(0, 0, originalCanvas.width, originalCanvas.height);
  const px = imgData.data;

  if (bits.length > px.length / 4) {
    alert("Payload exceeds image capacity.");
    return;
  }

  // Inject into Red channel LSB
  for (let i = 0; i < bits.length; i++) {
    const pixelIndex = i * 4;
    px[pixelIndex] = (px[pixelIndex] & ~1) | bits[i];
  }

  // Write modified pixels back
  origCtx.putImageData(imgData, 0, 0);

  // Trigger analysis immediately on canvas
  runForensicAnalysis();

  // Export clean PNG
  const link = document.createElement("a");
  link.download = "stego_evidence.png";
  link.href = originalCanvas.toDataURL("image/png");
  link.click();
});