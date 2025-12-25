const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const https = require("https");

const app = express();
const port = 4000;

app.use(express.json());
app.use(cors());

// CT Log Endpoints - Sử dụng Google CT logs
const CT_LOGS = [
  {
    name: "Google Argon2024",
    url: "https://ct.googleapis.com/logs/argon2024/",
    key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKATl4kmbI8vkT3yvdqIJbBb2gcHd2h7lBbNt0n4-1A0w9E5C8A5J5Q5R5S5T5U5V5W5X5Y5Z5A5B5C5D5E5F",
  },
  {
    name: "Google Xenon2024",
    url: "https://ct.googleapis.com/logs/xenon2024/",
    key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKATl4kmbI8vkT3yvdqIJbBb2gcHd2h7lBbNt0n4-1A0w9E5C8A5J5Q5R5S5T5U5V5W5X5Y5Z5A5B5C5D5E5F",
  },
  {
    name: "Cloudflare Nimbus2024",
    url: "https://ct.cloudflare.com/logs/nimbus2024/",
    key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKATl4kmbI8vkT3yvdqIJbBb2gcHd2h7lBbNt0n4-1A0w9E5C8A5J5Q5R5S5T5U5V5W5X5Y5Z5A5B5C5D5E5F",
  },
];

// Local CT Log Cache (Merkle Tree Structure)
class MerkleTree {
  constructor(entries = []) {
    this.entries = entries;
    this.tree = this.buildTree(entries);
  }

  buildTree(entries) {
    if (entries.length === 0) return null;
    if (entries.length === 1) return entries[0];

    const leaves = entries.map((entry, index) => ({
      data: entry,
      hash: this.hashEntry(entry),
      index,
    }));

    return this.buildTreeRecursive(leaves);
  }

  hashEntry(entry) {
    const data = typeof entry === "string" ? entry : JSON.stringify(entry);
    return crypto.createHash("sha256").update(data).digest("hex");
  }

  buildTreeRecursive(nodes) {
    if (nodes.length === 1) return nodes[0];

    const nextLevel = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i];
      const right = nodes[i + 1] || left; // Pad if odd
      const combined = left.hash + right.hash;
      nextLevel.push({
        left,
        right,
        hash: crypto.createHash("sha256").update(combined).digest("hex"),
      });
    }

    return this.buildTreeRecursive(nextLevel);
  }

  getRootHash() {
    return this.tree ? this.tree.hash : null;
  }

  generateProof(entryIndex) {
    // Simplified Merkle proof generation
    // In production, this should use proper Merkle tree traversal
    const entry = this.entries[entryIndex];
    if (!entry) return null;

    return {
      entry: entry,
      proof_path: this.getProofPath(entryIndex, 0),
      leaf_hash: this.hashEntry(entry),
    };
  }

  getProofPath(entryIndex, currentIndex) {
    // Simplified - returns empty path for now
    // Real implementation would traverse tree and collect sibling hashes
    return [];
  }

  verifyProof(proof, rootHash) {
    if (!proof || !rootHash) return false;

    let currentHash = proof.leaf_hash;
    for (const siblingHash of proof.proof_path) {
      const combined = currentHash < siblingHash
        ? currentHash + siblingHash
        : siblingHash + currentHash;
      currentHash = crypto.createHash("sha256").update(combined).digest("hex");
    }

    return currentHash === rootHash;
  }
}

// CT Log Storage
let ctLogs = new Map(); // domain -> certificate entries
let merkleTree = new MerkleTree();

/**
 * Tính toán SHA-256 fingerprint của certificate
 */
function calculateFingerprint(certificate) {
  if (typeof certificate === "string") {
    return crypto.createHash("sha256").update(certificate, "base64").digest("hex");
  }
  if (certificate && certificate.fingerprint) {
    return certificate.fingerprint;
  }
  // Extract from PEM or DER format
  const certData = typeof certificate === "object" 
    ? JSON.stringify(certificate) 
    : certificate;
  return crypto.createHash("sha256").update(certData).digest("hex");
}

/**
 * Lấy certificate từ domain sử dụng HTTPS
 */
async function fetchCertificateFromDomain(domain) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: domain,
        port: 443,
        method: "GET",
        rejectUnauthorized: false, // Allow self-signed for testing
      },
      (res) => {
        const cert = res.socket.getPeerCertificate(true);
        resolve(cert);
      }
    );

    req.on("error", (error) => {
      reject(error);
    });

    req.end();
  });
}

/**
 * Kiểm tra certificate trong CT logs
 */
function checkCertificateInCTLogs(domain, fingerprint) {
  const entries = ctLogs.get(domain) || [];
  const found = entries.find((entry) => entry.fingerprint === fingerprint);
  return found;
}

/**
 * Thêm certificate vào CT logs
 */
function addToCTLogs(domain, certificate, fingerprint) {
  if (!ctLogs.has(domain)) {
    ctLogs.set(domain, []);
  }

  const entry = {
    domain,
    fingerprint,
    certificate,
    timestamp: Date.now(),
    sct: generateSCT(domain, fingerprint), // Signed Certificate Timestamp
  };

  ctLogs.get(domain).push(entry);

  // Rebuild Merkle tree
  const allEntries = Array.from(ctLogs.values()).flat();
  merkleTree = new MerkleTree(allEntries.map((e) => e.fingerprint));

  return entry;
}

/**
 * Generate Signed Certificate Timestamp (SCT)
 */
function generateSCT(domain, fingerprint) {
  const sctData = {
    version: 0,
    log_id: crypto.createHash("sha256").update("CT_LOG_ID").digest("hex").substring(0, 32),
    timestamp: Math.floor(Date.now() / 1000),
    extensions: "",
    signature: crypto.createHash("sha256").update(domain + fingerprint).digest("hex"),
  };

  return Buffer.from(JSON.stringify(sctData)).toString("base64");
}

/**
 * Verify SCT
 */
function verifySCT(sct, domain, fingerprint) {
  try {
    const sctData = JSON.parse(Buffer.from(sct, "base64").toString());
    const expectedSignature = crypto
      .createHash("sha256")
      .update(domain + fingerprint)
      .digest("hex");
    return sctData.signature === expectedSignature;
  } catch (error) {
    return false;
  }
}

/**
 * API: Kiểm tra certificate
 */
app.post("/ct-check", async (req, res) => {
  try {
    const { domain, certificate } = req.body;
    if (!domain) {
      return res.status(400).json({ error: "Thiếu domain" });
    }

    // Extract domain from URL if needed
    let hostname = domain;
    try {
      const url = new URL(domain.startsWith("http") ? domain : `https://${domain}`);
      hostname = url.hostname;
    } catch (e) {
      // Assume it's already a hostname
    }

    // Calculate fingerprint
    let fingerprint;
    if (certificate) {
      fingerprint = calculateFingerprint(certificate);
    } else {
      // Try to fetch certificate from domain
      try {
        const cert = await fetchCertificateFromDomain(hostname);
        fingerprint = calculateFingerprint(cert);
      } catch (error) {
        console.error(`[CT Service] Lỗi lấy certificate từ ${hostname}:`, error);
      }
    }

    if (!fingerprint) {
      return res.status(400).json({ error: "Không thể xác định fingerprint" });
    }

    // Check in CT logs
    const ctEntry = checkCertificateInCTLogs(hostname, fingerprint);

    if (!ctEntry) {
      // Certificate not found - potential MitM or new certificate
      return res.json({
        domain: hostname,
        fingerprint: `SHA256:${fingerprint.substring(0, 44)}`,
        status: "warning",
        message: "⚠️ Chứng chỉ không tìm thấy trong CT Logs",
        mitm_status: "suspicious",
        ct_logs_checked: ctLogs.size,
        recommendation: "Certificate có thể là mới hoặc có dấu hiệu MitM attack",
      });
    }

    // Verify SCT
    const sctValid = verifySCT(ctEntry.sct, hostname, fingerprint);

    // Get Merkle proof
    const allEntries = Array.from(ctLogs.values()).flat();
    const entryIndex = allEntries.findIndex(
      (e) => e.domain === hostname && e.fingerprint === fingerprint
    );
    const proof = merkleTree.generateProof(entryIndex);

    const rootHash = merkleTree.getRootHash();
    const proofValid = proof ? merkleTree.verifyProof(proof, rootHash) : false;

    return res.json({
      domain: hostname,
      fingerprint: `SHA256:${fingerprint.substring(0, 44)}`,
      status: "valid",
      message: "✅ Chứng chỉ hợp lệ trong CT Logs",
      mitm_status: sctValid && proofValid ? "safe" : "warning",
      sct_valid: sctValid,
      merkle_proof_valid: proofValid,
      merkle_root: rootHash,
      timestamp: new Date(ctEntry.timestamp).toISOString(),
      ct_log_entry: {
        domain: ctEntry.domain,
        timestamp: ctEntry.timestamp,
        sct: ctEntry.sct,
      },
    });
  } catch (error) {
    console.error("[CT Service] Lỗi:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * API: Thêm certificate vào CT logs (mock - trong thực tế sẽ từ CA)
 */
app.post("/add-certificate", (req, res) => {
  try {
    const { domain, certificate, fingerprint } = req.body;
    if (!domain || !certificate) {
      return res.status(400).json({ error: "Thiếu domain hoặc certificate" });
    }

    const certFingerprint = fingerprint || calculateFingerprint(certificate);
    const entry = addToCTLogs(domain, certificate, certFingerprint);

    const rootHash = merkleTree.getRootHash();

    res.json({
      message: "✅ Đã thêm certificate vào CT Logs",
      domain: entry.domain,
      fingerprint: `SHA256:${certFingerprint.substring(0, 44)}`,
      merkle_root: rootHash,
      sct: entry.sct,
      timestamp: entry.timestamp,
    });
  } catch (error) {
    console.error("[CT Service] Lỗi:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * API: Lấy Merkle Root Hash
 */
app.get("/merkle-root", (req, res) => {
  const rootHash = merkleTree.getRootHash();
  res.json({
    merkle_root: rootHash,
    total_certificates: Array.from(ctLogs.values()).flat().length,
    total_domains: ctLogs.size,
  });
});

/**
 * API: Lấy danh sách CT logs
 */
app.get("/ct-logs", (req, res) => {
  const logs = Array.from(ctLogs.entries()).map(([domain, entries]) => ({
    domain,
    entries: entries.map((e) => ({
      fingerprint: `SHA256:${e.fingerprint.substring(0, 44)}`,
      timestamp: e.timestamp,
      sct: e.sct,
    })),
  }));

  res.json({
    total_domains: ctLogs.size,
    total_certificates: Array.from(ctLogs.values()).flat().length,
    logs,
  });
});

/**
 * API: Health check
 */
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "CT Certificate Transparency Service",
    version: "2.0.0",
    merkle_root: merkleTree.getRootHash(),
    total_certificates: Array.from(ctLogs.values()).flat().length,
  });
});

// Initialize with some test certificates
addToCTLogs("google.com", "MOCK_CERT_GOOGLE", "google_fingerprint_12345678901234567890123456789012");
addToCTLogs("facebook.com", "MOCK_CERT_FACEBOOK", "facebook_fingerprint_123456789012345678901234567890");

app.listen(port, () => {
  console.log(`🔐 CT Certificate Transparency Service đang chạy tại http://localhost:${port}`);
  console.log(`📊 Merkle Root: ${merkleTree.getRootHash()}`);
  console.log(`📝 Total certificates: ${Array.from(ctLogs.values()).flat().length}`);
});

