document.addEventListener("DOMContentLoaded", async () => {
  try {
    // Lấy tab hiện tại và hiển thị URL
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    
    const currentUrl = tab.url || "N/A";
    document.getElementById("current-url").textContent = currentUrl;

    // Đăng ký sự kiện click cho nút "Verify Certificate"
    document.getElementById("checkBtn").addEventListener("click", async () => {
      try {
        // Hiển thị trạng thái loading
        document.getElementById("status").innerHTML = `
          <div class="status-indicator">
            <i class="fas fa-spinner fa-spin"></i>
            Đang kiểm tra chứng chỉ...
          </div>
        `;
        
        document.getElementById("certDetails").style.display = "none";

        // Extract domain từ URL
        let domain = currentUrl;
        try {
          const url = new URL(currentUrl);
          domain = url.hostname;
        } catch (e) {
          // Nếu không phải URL hợp lệ, sử dụng như domain
        }

        // Gọi API server để kiểm tra chứng chỉ
        const response = await fetch("http://localhost:4000/ct-check", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain: domain }),
        });

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log("Dữ liệu từ server:", data);

        if (data.error) {
          document.getElementById("status").innerHTML = `
            <div class="status-indicator error">
              <i class="fas fa-exclamation-circle"></i>
              ❌ ${data.error}
            </div>
          `;
          return;
        }

        // Hiển thị kết quả chi tiết
        displayCertificateResults(data);

        // Lưu vào lịch sử
        saveToHistory(currentUrl, data);
      } catch (error) {
        console.error("[Popup] Lỗi khi gọi API:", error);
        document.getElementById("status").innerHTML = `
          <div class="status-indicator error">
            <i class="fas fa-exclamation-circle"></i>
            ❌ Lỗi: ${error.message}
          </div>
        `;
      }
    });

    // Tự động tải lịch sử khi popup mở
    loadHistory();
  } catch (error) {
    console.error("[Popup] Lỗi khi khởi tạo popup:", error);
    document.getElementById("status").innerHTML = `
      <div class="status-indicator error">
        <i class="fas fa-exclamation-circle"></i>
        ❌ Lỗi khi khởi tạo popup.
      </div>
    `;
  }
});

/**
 * Hiển thị kết quả kiểm tra certificate
 */
function displayCertificateResults(data) {
  const statusBox = document.getElementById("status");
  const certDetails = document.getElementById("certDetails");

  // Xác định icon và màu sắc dựa trên status
  let icon, color, statusText;
  
  if (data.mitm_status === "safe" && data.status === "valid") {
    icon = "fa-shield-alt";
    color = "green";
    statusText = "✅ An toàn - Chứng chỉ hợp lệ";
  } else if (data.mitm_status === "suspicious" || data.mitm_status === "warning") {
    icon = "fa-exclamation-triangle";
    color = "orange";
    statusText = "⚠️ Cảnh báo - Chứng chỉ đáng nghi";
  } else {
    icon = "fa-times-circle";
    color = "red";
    statusText = "❌ Nguy hiểm - Phát hiện MitM";
  }

  // Hiển thị status chính
  statusBox.innerHTML = `
    <div class="status-indicator ${color}">
      <i class="fas ${icon}"></i>
      ${statusText}
      <br>
      <small>${data.message || ""}</small>
    </div>
  `;

  // Hiển thị chi tiết
  document.getElementById("certFingerprint").textContent = data.fingerprint || "N/A";
  
  const statusBadge = data.status === "valid" 
    ? '<span style="color: green;">✓ Valid</span>'
    : '<span style="color: red;">✗ Invalid</span>';
  document.getElementById("certStatus").innerHTML = statusBadge;

  document.getElementById("certMerkleRoot").textContent = 
    data.merkle_root ? data.merkle_root.substring(0, 32) + "..." : "N/A";

  const sctStatus = data.sct_valid 
    ? '<span style="color: green;">✓ Valid</span>'
    : '<span style="color: orange;">⚠ Unknown</span>';
  document.getElementById("certSCT").innerHTML = sctStatus || "N/A";

  document.getElementById("certTimestamp").textContent = 
    data.timestamp ? new Date(data.timestamp).toLocaleString("vi-VN") : "N/A";

  certDetails.style.display = "block";
}

/**
 * Lưu lịch sử kiểm tra vào chrome.storage
 */
function saveToHistory(url, result) {
  chrome.storage.local.get("history", (data) => {
    let history = data.history || [];
    const newRecord = {
      url: url,
      result: {
        domain: result.domain,
        status: result.status,
        mitm_status: result.mitm_status,
        fingerprint: result.fingerprint,
        timestamp: result.timestamp || new Date().toISOString(),
      },
      time: new Date().toLocaleString("vi-VN"),
    };
    
    // Giới hạn lịch sử tối đa 50 bản ghi
    history.unshift(newRecord);
    if (history.length > 50) {
      history = history.slice(0, 50);
    }
    
    chrome.storage.local.set({ history }, () => {
      loadHistory();
    });
  });
}

/**
 * Hiển thị lịch sử kiểm tra từ chrome.storage
 */
function loadHistory() {
  chrome.storage.local.get("history", (data) => {
    const historyList = document.getElementById("historyList");
    historyList.innerHTML = "";
    
    const history = data.history || [];
    
    if (history.length === 0) {
      historyList.innerHTML = '<li class="history-empty">Chưa có lịch sử kiểm tra</li>';
      return;
    }

    history.forEach((item) => {
      const li = document.createElement("li");
      li.className = "history-item";
      
      const statusIcon = item.result.mitm_status === "safe" 
        ? '<i class="fas fa-shield-alt" style="color: green;"></i>'
        : '<i class="fas fa-exclamation-triangle" style="color: orange;"></i>';
      
      li.innerHTML = `
        <div class="history-item-header">
          ${statusIcon}
          <strong>${item.result.domain || new URL(item.url).hostname}</strong>
          <span class="history-time">${item.time}</span>
        </div>
        <div class="history-item-details">
          <small>Status: ${item.result.status} | MitM: ${item.result.mitm_status}</small>
        </div>
      `;
      
      // Click để xem chi tiết
      li.addEventListener("click", () => {
        displayCertificateResults(item.result);
      });
      
      historyList.appendChild(li);
    });
  });
}
