import { loadWasm, checkCertificate } from "./wasm_loader.js";

chrome.runtime.onInstalled.addListener(() => {
  console.log("[Background] CT Certificate Transparency Extension đã cài đặt.");
  loadWasm().catch((error) => {
    console.error("[Background] Lỗi khi tải WASM:", error);
  });
});

chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  if (message.action === "check_certificate") {
    try {
      const tabId = message.tabId;
      const url = new URL(message.url).hostname;
      console.log(`[Background] Kiểm tra chứng chỉ của: ${url}`);

      // Lấy chứng chỉ TLS từ trình duyệt
      const certData = await getCertificate(tabId);
      if (!certData) {
        throw new Error("Không thể lấy chứng chỉ.");
      }

      console.log(`[Background] Chứng chỉ TLS lấy được:`, certData);

      // Gửi chứng chỉ đến CT Service để xác minh
      const response = await fetch("http://localhost:4000/ct-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: url, certificate: certData }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      console.log(`[Background] Kết quả từ CT Service:`, data);

      // Xác minh Merkle Proof bằng WASM module
      if (data.merkle_root && data.ct_log_entry) {
        const merkleProof = data.merkle_proof || JSON.stringify({
          leaf_hash: data.fingerprint.replace("SHA256:", ""),
          proof_path: [],
        });

        const wasmResult = await checkCertificate(
          url,
          data.fingerprint,
          merkleProof,
          data.merkle_root
        );

        // Merge results
        data.wasm_verification = wasmResult;
        data.mitm_status = wasmResult.status === "safe" ? "safe" : data.mitm_status;
      }

      sendResponse(data);
    } catch (error) {
      console.error("[Background] Lỗi kiểm tra chứng chỉ:", error);
      sendResponse({ 
        error: error.message,
        domain: message.url ? new URL(message.url).hostname : "unknown",
        status: "error"
      });
    }
    return true; // Keep message channel open for async response
  }
  return false;
});

/**
 * Lấy certificate từ tab sử dụng Chrome Debugger API
 */
async function getCertificate(tabId) {
  return new Promise((resolve, reject) => {
    chrome.debugger.attach({ tabId: tabId }, "1.2", (attachError) => {
      if (chrome.runtime.lastError || attachError) {
        reject(new Error("Không thể attach debugger: " + (attachError || chrome.runtime.lastError.message)));
        return;
      }

      chrome.debugger.sendCommand(
        { tabId: tabId },
        "Network.enable",
        {},
        (enableError) => {
          if (enableError) {
            chrome.debugger.detach({ tabId: tabId }, () => {});
            reject(new Error("Không thể enable Network: " + enableError));
            return;
          }

          // Try to get certificate
          chrome.debugger.sendCommand(
            { tabId: tabId },
            "Network.getCertificate",
            { origin: "*" },
            (result) => {
              chrome.debugger.detach({ tabId: tabId }, () => {});
              
              if (chrome.runtime.lastError) {
                reject(new Error("Không thể lấy certificate: " + chrome.runtime.lastError.message));
              } else if (!result || !result.tableNames) {
                reject(new Error("Certificate không có sẵn từ debugger API"));
              } else {
                resolve(result);
              }
            }
          );
        }
      );
    });
  });
}
