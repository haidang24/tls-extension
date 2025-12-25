import init, { verify_certificate, verify_fingerprint, calculate_fingerprint } from "./pkg/wasm_verifier.js";

let wasmLoaded = false;

async function loadWasm() {
  if (wasmLoaded) {
    console.log("[WASM] Đã được tải trước đó.");
    return;
  }

  try {
    await init();
    wasmLoaded = true;
    console.log("[WASM] Đã tải thành công CT Verification Module.");
  } catch (error) {
    console.error("[WASM] Lỗi khi tải WASM:", error);
    throw error;
  }
}

/**
 * Xác minh certificate sử dụng Merkle proof
 */
async function checkCertificate(domain, fingerprint, merkle_proof, merkle_root) {
  try {
    if (!wasmLoaded) {
      await loadWasm();
    }

    // Verify fingerprint format
    const fingerprintValid = verify_fingerprint(fingerprint);
    if (!fingerprintValid) {
      console.warn("[WASM] Fingerprint format không hợp lệ:", fingerprint);
    }

    // Verify certificate với Merkle proof
    const merkleProofJson = typeof merkle_proof === "string" 
      ? merkle_proof 
      : JSON.stringify(merkle_proof);

    const resultJson = verify_certificate(
      domain,
      fingerprint,
      merkleProofJson,
      merkle_root || ""
    );

    const result = JSON.parse(resultJson);
    console.log("[WASM] Kết quả xác minh:", result);
    return result;
  } catch (error) {
    console.error("[WASM] Lỗi khi xác minh chứng chỉ:", error);
    return { 
      error: "Lỗi khi xác minh chứng chỉ.",
      status: "error",
      domain,
      fingerprint 
    };
  }
}

/**
 * Tính toán fingerprint từ certificate data
 */
async function computeFingerprint(certData) {
  try {
    if (!wasmLoaded) {
      await loadWasm();
    }

    const fingerprint = calculate_fingerprint(certData);
    return fingerprint;
  } catch (error) {
    console.error("[WASM] Lỗi khi tính fingerprint:", error);
    return null;
  }
}

export { loadWasm, checkCertificate, computeFingerprint };
