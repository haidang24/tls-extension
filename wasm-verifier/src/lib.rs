use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize)]
pub struct CertificateData {
    pub domain: String,
    pub fingerprint: String,
    pub merkle_proof: String,
    pub merkle_root: String,
    pub status: String,
    pub sct_valid: bool,
}

#[derive(Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_hash: String,
    pub proof_path: Vec<String>,
}

#[wasm_bindgen]
pub fn verify_certificate(
    domain: &str,
    fingerprint: &str,
    merkle_proof_json: &str,
    merkle_root: &str,
) -> String {
    // Parse Merkle proof
    let proof_result: Result<MerkleProof, _> = serde_json::from_str(merkle_proof_json);
    
    let is_valid = if let Ok(proof) = proof_result {
        verify_merkle_proof(&proof, fingerprint, merkle_root)
    } else {
        false
    };

    let status = if is_valid { "safe" } else { "danger" };

    let result = CertificateData {
        domain: domain.to_string(),
        fingerprint: fingerprint.to_string(),
        merkle_proof: merkle_proof_json.to_string(),
        merkle_root: merkle_root.to_string(),
        status: status.to_string(),
        sct_valid: is_valid,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}

/// Verify Merkle proof cho certificate
fn verify_merkle_proof(proof: &MerkleProof, fingerprint: &str, root_hash: &str) -> bool {
    if proof.proof_path.is_empty() {
        // Nếu không có proof path, kiểm tra leaf hash có khớp với fingerprint không
        let fingerprint_hash = hash_data(fingerprint);
        return proof.leaf_hash == fingerprint_hash && fingerprint_hash == root_hash;
    }

    // Tính toán hash từ leaf lên root
    let mut current_hash = proof.leaf_hash.clone();
    
    for sibling_hash in &proof.proof_path {
        // Combine hashes (parent = hash(left + right) hoặc hash(right + left))
        // Sử dụng thứ tự lexicographic để đảm bảo tính nhất quán
        let combined = if current_hash < *sibling_hash {
            format!("{}{}", current_hash, sibling_hash)
        } else {
            format!("{}{}", sibling_hash, current_hash)
        };
        
        current_hash = hash_data(&combined);
    }

    // So sánh với root hash
    current_hash == root_hash
}

/// Hash data sử dụng SHA-256
fn hash_data(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verify certificate fingerprint format
#[wasm_bindgen]
pub fn verify_fingerprint(fingerprint: &str) -> bool {
    // Kiểm tra format SHA256 fingerprint
    fingerprint.starts_with("SHA256:") || fingerprint.len() == 64
}

/// Calculate SHA-256 hash của certificate data
#[wasm_bindgen]
pub fn calculate_fingerprint(cert_data: &str) -> String {
    hash_data(cert_data)
}
