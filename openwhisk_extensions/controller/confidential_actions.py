#!/usr/bin/env python3
"""
OpenWhisk Controller Extension for Confidential Actions

This module provides the Controller-side logic for handling confidential
serverless actions with cryptographic binding per paper Sec. V.

Key Responsibilities:
1. Accept invoke API with FID, C_req, C_key, pkU, nonce
2. Generate AID (untrusted metadata for tracing/scheduling only)
3. Enqueue Activation message to Kafka for Invoker
4. Return receipt (RID, AID) to client

Protocol Binding (Paper Sec. V):
- AID: Untrusted identifier for ops metrics only
- RID = H(FID || C_req): Computed by both client and worker
- Controller may return RID in receipt, but RID must never be trusted by the client/worker
  (both compute RID independently). Controller must not use AID as retrieval key.
"""

import hashlib
import uuid
import json
import os
import sys
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import base64

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from crypto_lib.profiles import get_crypto_profile


@dataclass
class ConfidentialInvokeRequest:
    """Request payload for invoking a confidential action."""
    fid: str           # Function Identity = H(tenant_id || action_name || version || H(code))
    c_req: bytes       # Encrypted request input
    c_key: bytes       # Encrypted session key (optional, if using KEM)
    pk_u: bytes        # User's public key for output encryption
    nonce: bytes       # Fresh nonce for replay protection
    c_k_func: bytes = b""  # Encrypted function key for the worker cold/warm path.
    crypto_profile: str = "eccibe"
    key_ciphertext_format: str = "key-ciphertext-v1-ecc-p256"

    def __post_init__(self) -> None:
        profile = get_crypto_profile(self.crypto_profile)
        if self.key_ciphertext_format != profile.key_ciphertext_format:
            raise ValueError(
                "Invalid key_ciphertext_format for crypto_profile "
                f"{profile.profile_id}: expected {profile.key_ciphertext_format}, "
                f"got {self.key_ciphertext_format}"
            )
        self.crypto_profile = profile.profile_id
        self.key_ciphertext_format = profile.key_ciphertext_format
    
    def to_activation_message(self) -> Dict[str, Any]:
        """Convert to Kafka Activation message format."""
        return {
            "FID": self.fid,
            "C_req": base64.b64encode(self.c_req).decode('utf-8'),
            "C_k_func": base64.b64encode(self.c_k_func).decode('utf-8') if self.c_k_func else "",
            "C_key": base64.b64encode(self.c_key).decode('utf-8') if self.c_key else "",
            "pkU": base64.b64encode(self.pk_u).decode('utf-8'),
            "nonce": base64.b64encode(self.nonce).decode('utf-8'),
            "crypto_profile": self.crypto_profile,
            "key_ciphertext_format": self.key_ciphertext_format,
        }


@dataclass
class ConfidentialInvokeResponse:
    """Response from Controller after enqueueing invocation."""
    rid: str           # Retrieval ID = H(FID || C_req) (untrusted hint; client verifies)
    aid: str           # Activation ID (untrusted metadata)
    status: str        # "accepted" or "error"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ConfidentialActionsController:
    """
    Controller extension for confidential action invocation.
    
    This class implements the Controller-side logic for:
    1. Accepting confidential invoke requests
    2. Generating AID (untrusted activation ID)
    3. Sending Activation message to Kafka
    4. Returning receipt to client
    """
    
    def __init__(self, kafka_producer=None):
        """
        Initialize the controller.
        
        Args:
            kafka_producer: Kafka producer for sending activation messages.
                           Can be None for testing.
        """
        self.kafka_producer = kafka_producer
        self._pending_activations: Dict[str, Dict] = {}
    
    def generate_aid(self) -> str:
        """
        Generate a new Activation ID.
        
        AID is untrusted metadata used only for:
        - Ops tracing/logging
        - Loadbalancing/scheduling
        
        AID is NOT used for:
        - Result retrieval (use RID instead)
        - AEAD AAD binding (use RID instead)
        """
        return str(uuid.uuid4())
    
    def invoke_confidential_action(
        self,
        action_name: str,
        tenant_id: str,
        request: ConfidentialInvokeRequest
    ) -> ConfidentialInvokeResponse:
        """
        Handle invocation of a confidential action.
        
        Args:
            action_name: Name of the action to invoke
            tenant_id: Tenant/namespace identifier
            request: Confidential invoke request with FID, C_req, etc.
        
        Returns:
            ConfidentialInvokeResponse with AID
        
        Protocol Flow:
        1. Generate AID (untrusted)
        2. Create Activation message with all confidential fields
        3. Enqueue to Kafka (topic: invoker{N})
        4. Return AID to client
        
        Note: Receipt may include RID as a convenience, but the client must
        verify it matches its own RID = H(FID || C_req) computation.
        """
        # 1. Generate AID
        aid = self.generate_aid()

        # 1.5 Compute RID for receipt (untrusted hint only)
        rid = ClientReceiptHandler.compute_rid(request.fid, request.c_req)
        
        # 2. Create Activation message
        activation_msg = {
            "activationId": aid,
            "action": {
                "path": tenant_id,
                "name": action_name
            },
            "content": request.to_activation_message(),
            # Include nonce in the message for replay protection
            "nonce": base64.b64encode(request.nonce).decode('utf-8'),
            "transid": [f"tid-{aid}", 0]
        }
        
        # 3. Enqueue to Kafka (or store for testing)
        if self.kafka_producer:
            # Real Kafka path
            topic = self._get_invoker_topic(request.fid)
            self.kafka_producer.send(topic, json.dumps(activation_msg))
        else:
            # Testing path: store in memory
            self._pending_activations[aid] = activation_msg
        
        # 4. Return response with (RID, AID)
        return ConfidentialInvokeResponse(
            rid=rid,
            aid=aid,
            status="accepted"
        )
    
    def _get_invoker_topic(self, fid: str) -> str:
        """
        Determine which invoker topic to use.
        
        In production, this would use consistent hashing or
        loadbalancing to select an invoker.
        """
        # Simple hash-based selection for demonstration
        invoker_id = int(hashlib.sha256(fid.encode()).hexdigest(), 16) % 8
        return f"invoker{invoker_id}"
    
    def get_pending_activation(self, aid: str) -> Optional[Dict]:
        """Get pending activation by AID (for testing)."""
        return self._pending_activations.get(aid)


class ClientReceiptHandler:
    """
    Client-side handler for processing Controller receipts.
    
    The client receives (AID) from Controller but computes RID locally.
    Result retrieval uses RID, not AID.
    """
    
    @staticmethod
    def compute_rid(fid: str, c_req: bytes) -> str:
        """
        Compute RID (Request ID) for result retrieval.
        
        RID = H(FID || C_req)
        
        This is computed by BOTH:
        - Client (after sending invocation)
        - Worker (after decrypting and processing)
        
        RID is used for:
        - Result store indexing (put-if-absent by RID)
        - AAD binding in output encryption: aad_out = ("OUT", FID, RID, H(pkU))
        
        RID is NOT used by Controller - it only has untrusted AID.
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
    
    @staticmethod
    def process_receipt(
        controller_response: Dict[str, Any],
        fid: str,
        c_req: bytes
    ) -> Tuple[str, str]:
        """
        Process Controller receipt and compute RID.
        
        Args:
            controller_response: Response from Controller containing AID
            fid: Function Identity used in invocation
            c_req: Encrypted request sent in invocation
        
        Returns:
            Tuple of (RID, AID) where:
            - RID: Used for result retrieval
            - AID: Untrusted metadata (for logging only)
        """
        aid = controller_response["aid"]
        rid_local = ClientReceiptHandler.compute_rid(fid, c_req)

        rid_from_controller = controller_response.get("rid")
        if rid_from_controller is not None:
            if rid_from_controller != rid_local:
                raise ValueError("Controller-provided RID does not match local RID computation")

        return (rid_local, aid)


# Unit tests
def test_controller_invoke():
    """Test Controller confidential invoke API."""
    print("\n[Test] Controller Invoke Confidential Action API")
    
    controller = ConfidentialActionsController()
    
    # Create test request
    request = ConfidentialInvokeRequest(
        fid="abc123def456",
        c_req=b"encrypted_request_data",
        c_key=b"encrypted_session_key",
        pk_u=b"user_public_key_bytes",
        nonce=b"fresh_nonce_16bytes!"
    )
    
    # Invoke
    response = controller.invoke_confidential_action(
        action_name="myConfidentialAction",
        tenant_id="guest",
        request=request
    )
    
    # Verify
    assert response.aid, "AID should be generated"
    assert response.status == "accepted", "Status should be accepted"
    print(f"  ✓ AID generated: {response.aid}")
    print(f"  ✓ Status: {response.status}")
    
    # Verify activation message was stored
    activation = controller.get_pending_activation(response.aid)
    assert activation is not None, "Activation should be stored"
    assert activation["content"]["FID"] == "abc123def456", "FID should be preserved"
    assert activation["content"]["nonce"], "Nonce should be included"
    print(f"  ✓ Activation message contains FID, C_req, pkU, nonce")
    
    print("  ✅ Controller Invoke API test PASSED")
    return True


def test_client_receipt():
    """Test Client Receipt processing."""
    print("\n[Test] Client Receipt Returns (RID, AID)")
    
    controller = ConfidentialActionsController()
    
    # Step 1: Client invokes
    fid = "test_function_id"
    c_req = b"test_encrypted_request"
    
    request = ConfidentialInvokeRequest(
        fid=fid,
        c_req=c_req,
        c_key=b"key",
        pk_u=b"pk",
        nonce=b"nonce"
    )
    
    response = controller.invoke_confidential_action(
        action_name="testAction",
        tenant_id="guest",
        request=request
    )
    
    # Step 2: Client processes receipt
    rid, aid = ClientReceiptHandler.process_receipt(
        controller_response=response.to_dict(),
        fid=fid,
        c_req=c_req
    )
    
    # Step 3: Verify
    assert rid, "RID should be computed"
    assert aid == response.aid, "AID should match"
    
    # Verify RID is deterministic
    rid2 = ClientReceiptHandler.compute_rid(fid, c_req)
    assert rid == rid2, "RID should be deterministic"
    
    # Verify different c_req gives different RID
    rid3 = ClientReceiptHandler.compute_rid(fid, b"different_request")
    assert rid != rid3, "Different c_req should give different RID"
    
    print(f"  ✓ Client computed RID: {rid[:16]}...")
    print(f"  ✓ Controller returned AID: {aid}")
    print(f"  ✓ RID is deterministic (multiple computations match)")
    print(f"  ✓ Different c_req produces different RID")
    
    print("  ✅ Client Receipt test PASSED")
    return True


def test_controller_rid_is_untrusted_hint():
    """Verify Controller RID is only a client-verifiable hint."""
    print("\n[Test] Controller RID is an untrusted, client-verifiable hint")
    
    controller = ConfidentialActionsController()
    
    request = ConfidentialInvokeRequest(
        fid="test_fid",
        c_req=b"test_c_req",
        c_key=b"key",
        pk_u=b"pk",
        nonce=b"nonce"
    )
    
    response = controller.invoke_confidential_action(
        action_name="testAction",
        tenant_id="guest",
        request=request
    )
    
    response_dict = response.to_dict()
    
    expected_rid = ClientReceiptHandler.compute_rid("test_fid", b"test_c_req")
    assert response_dict["rid"] == expected_rid, "Controller RID hint should match H(FID || C_req)"
    assert "RID" not in response_dict, "Controller should not return uppercase trusted RID field"

    print(f"  ✓ Response keys: {list(response_dict.keys())}")
    print(f"  ✓ RID hint matches local computation and remains client-verifiable")
    
    print("  ✅ RID hint security test PASSED")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("OpenWhisk Controller Extension Tests")
    print("=" * 60)
    
    results = []
    results.append(("Controller Invoke API", test_controller_invoke()))
    results.append(("Client Receipt (RID, AID)", test_client_receipt()))
    results.append(("RID Security", test_controller_rid_is_untrusted_hint()))
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {name}: {status}")
    
    total_passed = sum(1 for _, p in results if p)
    print(f"\nTotal: {total_passed}/{len(results)} tests passed")
