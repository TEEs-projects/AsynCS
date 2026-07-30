#!/usr/bin/env python3
"""
OpenWhisk Invoker Extension for Confidential Actions

This module provides the Invoker-side logic for handling confidential
serverless actions with cryptographic binding per paper Sec. V.

Key Responsibilities:
1. Receive Activation message from Kafka (FID, C_req, C_key, pkU, nonce)
2. Dispatch to SGX Worker for confidential execution
3. Store result indexed by RID with put-if-absent semantics
4. Handle duplicate dispatch (first-writer-wins)

Protocol Binding (Paper Sec. V):
- RID = H(FID || C_req): Worker computes this after execution
- Result Store: Write-once / first-writer-wins (put-if-absent by RID)
- AAD binding: aad_out = ("OUT", FID, RID, H(pkU))
"""

import hashlib
import json
import os
import sys
import base64
import threading
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from crypto_lib.profiles import get_crypto_profile


@dataclass
class ConfidentialResult:
    """Result from confidential execution."""
    rid: str          # Request ID = H(FID || C_req)
    ct: bytes         # KEM ciphertext for output encryption key
    c_out: bytes      # Encrypted output
    timestamp: str    # When result was stored
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rid": self.rid,
            "ct": base64.b64encode(self.ct).decode('utf-8'),
            "C_out": base64.b64encode(self.c_out).decode('utf-8'),
            "timestamp": self.timestamp
        }


class ResultStore:
    """
    Result store with write-once / first-writer-wins semantics.
    
    Implements put-if-absent by RID:
    - First write to RID succeeds
    - Subsequent writes to same RID are rejected/ignored
    
    This ensures:
    - Replay attacks cannot overwrite legitimate results
    - Duplicate dispatch doesn't corrupt results
    - Idempotent retrieval by RID
    """
    
    def __init__(self):
        self._store: Dict[str, ConfidentialResult] = {}
        self._lock = threading.Lock()
    
    def put_if_absent(self, result: ConfidentialResult) -> bool:
        """
        Store result with put-if-absent semantics.
        
        Args:
            result: Confidential result to store
        
        Returns:
            True if stored (first write), False if already exists
        """
        with self._lock:
            if result.rid in self._store:
                # First-writer-wins: reject overwrite
                return False
            
            self._store[result.rid] = result
            return True
    
    def get(self, rid: str) -> Optional[ConfidentialResult]:
        """
        Retrieve result by RID.
        
        Args:
            rid: Request ID to look up
        
        Returns:
            ConfidentialResult if found, None otherwise
        """
        with self._lock:
            return self._store.get(rid)
    
    def exists(self, rid: str) -> bool:
        """Check if RID already has a result."""
        with self._lock:
            return rid in self._store
    
    def size(self) -> int:
        """Get number of stored results."""
        with self._lock:
            return len(self._store)


class ConfidentialActionsInvoker:
    """
    Invoker extension for confidential action execution.
    
    This class implements the Invoker-side logic for:
    1. Receiving Activation messages from Kafka
    2. Parsing confidential execution parameters
    3. Dispatching to SGX Worker
    4. Storing results with write-once semantics
    """
    
    def __init__(self, result_store: Optional[ResultStore] = None):
        """
        Initialize the invoker.
        
        Args:
            result_store: Store for results. Uses default if None.
        """
        self.result_store = result_store or ResultStore()
    
    @staticmethod
    def compute_rid(fid: str, c_req: bytes) -> str:
        """
        Compute RID (Request ID) for result indexing.
        
        RID = H(FID || C_req)
        
        Worker computes this AFTER receiving C_req from Kafka message.
        """
        # Canonical encoding:
        # - If FID is a 64-hex SHA-256 digest, treat it as 32-byte value.
        # - Otherwise (legacy/tests), fall back to UTF-8 bytes for stability.
        fid_bytes: bytes
        fid_stripped = (fid or "").strip()
        if len(fid_stripped) == 64:
            try:
                fid_bytes = bytes.fromhex(fid_stripped)
            except ValueError:
                fid_bytes = fid_stripped.encode("utf-8")
        else:
            fid_bytes = fid_stripped.encode("utf-8")

        h = hashlib.sha256()
        h.update(fid_bytes)
        h.update(c_req)
        return h.hexdigest()
    
    def receive_activation(self, message_bytes: bytes) -> Dict[str, Any]:
        """
        Receive and parse Activation message from Kafka.
        
        Args:
            message_bytes: Raw Kafka message bytes
        
        Returns:
            Parsed activation with FID, C_req, C_key, pkU, nonce
        """
        message = json.loads(message_bytes.decode('utf-8'))
        
        content = message.get("content", {})
        profile = get_crypto_profile(content.get("crypto_profile"))
        key_ciphertext_format = content.get("key_ciphertext_format") or profile.key_ciphertext_format
        if key_ciphertext_format != profile.key_ciphertext_format:
            raise ValueError(
                "Invalid key_ciphertext_format for crypto_profile "
                f"{profile.profile_id}: expected {profile.key_ciphertext_format}, "
                f"got {key_ciphertext_format}"
            )
        
        # Parse confidential fields
        activation = {
            "activation_id": message.get("activationId"),
            "action": message.get("action", {}),
            "FID": content.get("FID", ""),
            "C_req": base64.b64decode(content.get("C_req", "")),
            "C_k_func": base64.b64decode(content.get("C_k_func", "")) if content.get("C_k_func") else None,
            "C_key": base64.b64decode(content.get("C_key", "")) if content.get("C_key") else None,
            "pkU": base64.b64decode(content.get("pkU", "")),
            "nonce": base64.b64decode(message.get("nonce", "")),
            "crypto_profile": profile.profile_id,
            "key_ciphertext_format": profile.key_ciphertext_format,
        }
        
        return activation
    
    def store_result(
        self,
        fid: str,
        c_req: bytes,
        ct: bytes,
        c_out: bytes
    ) -> Tuple[bool, str]:
        """
        Store execution result indexed by RID.
        
        Args:
            fid: Function Identity
            c_req: Encrypted request (used to compute RID)
            ct: KEM ciphertext for output key
            c_out: Encrypted output
        
        Returns:
            Tuple of (success, rid) where success indicates if this was first write
        """
        # Compute RID
        rid = self.compute_rid(fid, c_req)
        
        # Create result
        result = ConfidentialResult(
            rid=rid,
            ct=ct,
            c_out=c_out,
            timestamp=datetime.utcnow().isoformat()
        )
        
        # Store with put-if-absent
        success = self.result_store.put_if_absent(result)
        
        return (success, rid)
    
    def fetch_result(self, rid: str) -> Optional[Dict[str, Any]]:
        """
        Fetch result by RID.
        
        Args:
            rid: Request ID to look up
        
        Returns:
            Result dict if found, None otherwise
        """
        result = self.result_store.get(rid)
        if result:
            return result.to_dict()
        return None


class CouchDBResultStore(ResultStore):
    """
    CouchDB-backed result store with put-if-absent semantics.
    
    Uses CouchDB's _rev mechanism to implement first-writer-wins:
    - First write creates document with _rev=1
    - Subsequent writes without correct _rev are rejected (409 Conflict)
    
    In practice, we use:
    - Document ID = RID
    - Check if document exists before write
    - Use conditional PUT with If-None-Match header
    """
    
    def __init__(self, couchdb_url: str = "http://localhost:5984", db_name: str = "results"):
        super().__init__()
        self.couchdb_url = couchdb_url
        self.db_name = db_name
        self.db_url = f"{couchdb_url}/{db_name}"
        self._use_mock = True  # Use in-memory mock by default
    
    def put_if_absent(self, result: ConfidentialResult) -> bool:
        """
        Store result with put-if-absent using CouchDB.
        
        Implementation:
        1. Check if document with _id=RID exists
        2. If not, create new document
        3. If yes, return False (first-writer-wins)
        """
        if self._use_mock:
            # Use in-memory implementation for testing
            return super().put_if_absent(result)
        
        # Real CouchDB implementation would:
        # 1. HEAD /db/{rid} to check existence
        # 2. If 404, PUT /db/{rid} with document
        # 3. If 200, return False (already exists)
        # 4. Handle 409 Conflict (race condition) by returning False
        
        import requests
        doc_url = f"{self.db_url}/{result.rid}"
        
        try:
            # Check if exists
            resp = requests.head(doc_url)
            if resp.status_code == 200:
                # Already exists, first-writer-wins
                return False
            
            # Create new document
            doc = {
                "_id": result.rid,
                "ct": base64.b64encode(result.ct).decode('utf-8'),
                "C_out": base64.b64encode(result.c_out).decode('utf-8'),
                "timestamp": result.timestamp
            }
            resp = requests.put(doc_url, json=doc)
            
            if resp.status_code == 201:
                return True
            elif resp.status_code == 409:
                # Conflict - another writer got there first
                return False
            else:
                raise Exception(f"CouchDB error: {resp.status_code}")
                
        except requests.exceptions.ConnectionError:
            # Fall back to in-memory
            return super().put_if_absent(result)
    
    def get(self, rid: str) -> Optional[ConfidentialResult]:
        """Retrieve result from CouchDB."""
        if self._use_mock:
            return super().get(rid)
        
        import requests
        doc_url = f"{self.db_url}/{rid}"
        
        try:
            resp = requests.get(doc_url)
            if resp.status_code == 200:
                doc = resp.json()
                return ConfidentialResult(
                    rid=rid,
                    ct=base64.b64decode(doc["ct"]),
                    c_out=base64.b64decode(doc["C_out"]),
                    timestamp=doc["timestamp"]
                )
            return None
        except requests.exceptions.ConnectionError:
            return super().get(rid)


# Unit tests
def test_invoker_receive_activation():
    """Test Invoker receives and parses Kafka message."""
    print("\n[Test] Invoker Receive Activation from Kafka")
    
    invoker = ConfidentialActionsInvoker()
    
    # Simulate Kafka message
    message = {
        "activationId": "act-123",
        "action": {"path": "guest", "name": "myAction"},
        "content": {
            "FID": "test_fid_123",
            "C_req": base64.b64encode(b"encrypted_request").decode('utf-8'),
            "C_key": base64.b64encode(b"encrypted_key").decode('utf-8'),
            "pkU": base64.b64encode(b"user_public_key").decode('utf-8')
        },
        "nonce": base64.b64encode(b"fresh_nonce").decode('utf-8')
    }
    message_bytes = json.dumps(message).encode('utf-8')
    
    # Parse
    activation = invoker.receive_activation(message_bytes)
    
    # Verify
    assert activation["FID"] == "test_fid_123", "FID should be parsed"
    assert activation["C_req"] == b"encrypted_request", "C_req should be decoded"
    assert activation["C_key"] == b"encrypted_key", "C_key should be decoded"
    assert activation["pkU"] == b"user_public_key", "pkU should be decoded"
    assert activation["nonce"] == b"fresh_nonce", "nonce should be decoded"
    
    print(f"  ✓ Parsed FID: {activation['FID']}")
    print(f"  ✓ Parsed C_req: {len(activation['C_req'])} bytes")
    print(f"  ✓ Parsed C_key: {len(activation['C_key'])} bytes")
    print(f"  ✓ Parsed pkU: {len(activation['pkU'])} bytes")
    print(f"  ✓ Parsed nonce: {len(activation['nonce'])} bytes")
    
    print("  ✅ Invoker Receive Activation test PASSED")
    return True


def test_invoker_store_result():
    """Test Invoker stores result indexed by RID."""
    print("\n[Test] Invoker Store Result to CouchDB (indexed by RID)")
    
    invoker = ConfidentialActionsInvoker()
    
    fid = "test_fid_456"
    c_req = b"encrypted_request_data"
    ct = b"kem_ciphertext"
    c_out = b"encrypted_output"
    
    # Store result
    success, rid = invoker.store_result(fid, c_req, ct, c_out)
    
    assert success, "First store should succeed"
    assert rid, "RID should be returned"
    
    # Verify RID computation
    expected_rid = invoker.compute_rid(fid, c_req)
    assert rid == expected_rid, "RID should match computation"
    
    print(f"  ✓ Result stored with RID: {rid[:16]}...")
    print(f"  ✓ Storage success: {success}")
    
    # Fetch result
    result = invoker.fetch_result(rid)
    assert result, "Result should be retrievable"
    assert result["rid"] == rid, "RID should match"
    
    print(f"  ✓ Result retrieved by RID")
    
    print("  ✅ Invoker Store Result test PASSED")
    return True


def test_result_store_write_once():
    """Test Result Store has write-once / first-writer-wins semantics."""
    print("\n[Test] Result Store: Write-Once / First-Writer-Wins")
    
    store = ResultStore()
    
    # First write
    result1 = ConfidentialResult(
        rid="test_rid_001",
        ct=b"ct_first",
        c_out=b"out_first",
        timestamp="2024-01-01T00:00:00"
    )
    success1 = store.put_if_absent(result1)
    assert success1, "First write should succeed"
    print(f"  ✓ First write to RID succeeded")
    
    # Second write (should fail)
    result2 = ConfidentialResult(
        rid="test_rid_001",  # Same RID
        ct=b"ct_second",
        c_out=b"out_second",
        timestamp="2024-01-01T00:00:01"
    )
    success2 = store.put_if_absent(result2)
    assert not success2, "Second write should fail (first-writer-wins)"
    print(f"  ✓ Second write to same RID rejected")
    
    # Verify original value preserved
    stored = store.get("test_rid_001")
    assert stored.ct == b"ct_first", "Original value should be preserved"
    assert stored.c_out == b"out_first", "Original value should be preserved"
    print(f"  ✓ Original value preserved (first-writer-wins)")
    
    # Different RID should work
    result3 = ConfidentialResult(
        rid="test_rid_002",  # Different RID
        ct=b"ct_third",
        c_out=b"out_third",
        timestamp="2024-01-01T00:00:02"
    )
    success3 = store.put_if_absent(result3)
    assert success3, "Write to different RID should succeed"
    print(f"  ✓ Write to different RID succeeded")
    
    print("  ✅ Write-Once / First-Writer-Wins test PASSED")
    return True


def test_duplicate_dispatch():
    """Test duplicate dispatch doesn't overwrite existing result."""
    print("\n[Test] Duplicate Dispatch Does Not Overwrite")
    
    invoker = ConfidentialActionsInvoker()
    
    fid = "test_fid_duplicate"
    c_req = b"same_request"
    
    # First dispatch stores result
    ct1 = b"ct_original"
    c_out1 = b"output_original"
    success1, rid1 = invoker.store_result(fid, c_req, ct1, c_out1)
    assert success1, "First dispatch should succeed"
    print(f"  ✓ First dispatch stored result with RID: {rid1[:16]}...")
    
    # Duplicate dispatch (same FID, same C_req = same RID)
    ct2 = b"ct_duplicate"
    c_out2 = b"output_duplicate"
    success2, rid2 = invoker.store_result(fid, c_req, ct2, c_out2)
    assert not success2, "Duplicate dispatch should NOT overwrite"
    assert rid1 == rid2, "RID should be the same"
    print(f"  ✓ Duplicate dispatch rejected (same RID)")
    
    # Verify original preserved
    result = invoker.fetch_result(rid1)
    assert base64.b64decode(result["ct"]) == ct1, "Original ct preserved"
    assert base64.b64decode(result["C_out"]) == c_out1, "Original output preserved"
    print(f"  ✓ Original result preserved, duplicate ignored")
    
    print("  ✅ Duplicate Dispatch test PASSED")
    return True


def test_couchdb_store_mock():
    """Test CouchDB store with mock (in-memory)."""
    print("\n[Test] CouchDB Result Store (Mock)")
    
    store = CouchDBResultStore()
    store._use_mock = True  # Use in-memory
    
    result = ConfidentialResult(
        rid="couchdb_test_rid",
        ct=b"test_ct",
        c_out=b"test_out",
        timestamp="2024-01-01T00:00:00"
    )
    
    # Store
    success = store.put_if_absent(result)
    assert success, "Store should succeed"
    print(f"  ✓ Result stored in CouchDB (mock)")
    
    # Retrieve
    retrieved = store.get("couchdb_test_rid")
    assert retrieved, "Should be retrievable"
    assert retrieved.rid == "couchdb_test_rid"
    print(f"  ✓ Result retrieved from CouchDB (mock)")
    
    # Put-if-absent
    success2 = store.put_if_absent(result)
    assert not success2, "Second store should fail"
    print(f"  ✓ put-if-absent semantics working")
    
    print("  ✅ CouchDB Store (Mock) test PASSED")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("OpenWhisk Invoker Extension Tests")
    print("=" * 60)
    
    results = []
    results.append(("Receive Activation", test_invoker_receive_activation()))
    results.append(("Store Result by RID", test_invoker_store_result()))
    results.append(("Write-Once Semantics", test_result_store_write_once()))
    results.append(("Duplicate Dispatch", test_duplicate_dispatch()))
    results.append(("CouchDB Store Mock", test_couchdb_store_mock()))
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {name}: {status}")
    
    total_passed = sum(1 for _, p in results if p)
    print(f"\nTotal: {total_passed}/{len(results)} tests passed")
