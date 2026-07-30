import sys
import os
import time
import subprocess
import requests
import base64
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from client_sdk.sdk import ClientSDK

def test_integration():
    print("Starting Integration Test...")
    
    # 1. Start KMS
    print("Starting KMS...")
    
    # Get absolute path to project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)  # parent of tests/
    kms_dir = os.path.join(project_root, "sgx_kms")
    
    # Use log files instead of PIPE to avoid blocking when buffer fills
    kms_stdout = open("/tmp/kms_stdout.log", "w")
    kms_stderr = open("/tmp/kms_stderr.log", "w")
    
    # Run KMS using shell command with proper library path
    kms_proc = subprocess.Popen(
        f"cd {kms_dir} && ./sgx_kms",
        shell=True,
        stdout=kms_stdout,
        stderr=kms_stderr,
    )
    
    # Wait for KMS to be ready
    time.sleep(3)
    if kms_proc.poll() is not None:
        print("KMS failed to start")
        kms_stderr.close()
        with open("/tmp/kms_stderr.log", "r") as f:
            print(f.read())
        return

    # 2. Start Docker Container
    print("Starting Docker Container...")
    # Remove any existing container first
    subprocess.run(["docker", "rm", "-f", "sgx-worker-test"], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Use --network host to allow container to access KMS on localhost
    # Pass SGX devices, run in detached mode
    subprocess.run([
        "docker", "run", "-d", "--network", "host", 
        "--device", "/dev/sgx_enclave", "--device", "/dev/sgx_provision",
        "--name", "sgx-worker-test", "sgx-worker-runtime"
    ], check=True)
    
    time.sleep(8) # Give Docker more time to start
    
    try:
        # 3. Prepare Data
        # sdk = ClientSDK() # SDK uses IBE, but we use Mock Symmetric Key for this test
        fid = "default_fid"
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        mock_key = b'\xBB' * 16
        aesgcm = AESGCM(mock_key)

        # Encrypt WASM
        wasm_path = os.path.join(project_root, "sgx_worker", "test.wasm")
        if not os.path.exists(wasm_path):
            print(f"WASM file not found: {wasm_path}")
            return

        with open(wasm_path, "rb") as f:
            wasm_data = f.read()
        
        # Format: IV(12) + TAG(16) + Ciphertext
        nonce = os.urandom(12)
        ct_and_tag = aesgcm.encrypt(nonce, wasm_data, None)
        tag = ct_and_tag[-16:]
        ciphertext = ct_and_tag[:-16]
        encrypted_wasm = nonce + tag + ciphertext

        wasm_b64 = base64.b64encode(encrypted_wasm).decode('utf-8')
        
        # Encrypt Input
        input_data = b"Hello World"
        nonce = os.urandom(12)
        ct_and_tag = aesgcm.encrypt(nonce, input_data, None)
        tag = ct_and_tag[-16:]
        ciphertext = ct_and_tag[:-16]
        encrypted_input = nonce + tag + ciphertext

        input_b64 = base64.b64encode(encrypted_input).decode('utf-8')
        
        # 4. Send /init
        print("Sending /init...")
        init_payload = {"value": {"code": wasm_b64}}
        try:
            resp = requests.post("http://localhost:8080/init", json=init_payload)
            print(f"/init response: {resp.status_code} {resp.text}")
            if resp.status_code != 200:
                raise Exception("Init failed")
        except requests.exceptions.ConnectionError:
            print("Failed to connect to Docker container. Is it running?")
            # Check docker logs
            subprocess.run(["docker", "logs", "sgx-worker-test"])
            raise

        # 5. Send /run
        print("Sending /run...")
        run_payload = {"value": {"encrypted_input": input_b64}}
        resp = requests.post("http://localhost:8080/run", json=run_payload)
        print(f"/run response: {resp.status_code} {resp.text}")
        if resp.status_code != 200:
            raise Exception("Run failed")
            
        # 6. Decrypt Result
        result_json = resp.json()
        encrypted_result_b64 = result_json.get("encrypted_result")
        if not encrypted_result_b64:
             print("No encrypted result in response")
             print(result_json)
             raise Exception("No result")

        encrypted_result = base64.b64decode(encrypted_result_b64)
        
        nonce = encrypted_result[:12]
        tag = encrypted_result[12:28]
        ciphertext = encrypted_result[28:]
        
        decrypted_result = aesgcm.decrypt(nonce, ciphertext + tag, None)
        print(f"Decrypted Result: {decrypted_result}")
        
        print("[PASS] Integration Test Passed")

    except Exception as e:
        print(f"[FAIL] Exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("Cleaning up...")
        kms_proc.terminate()
        kms_stdout.close()
        kms_stderr.close()
        subprocess.run(["docker", "stop", "sgx-worker-test"])
        # Print KMS logs for debugging
        print("\n--- KMS Logs ---")
        with open("/tmp/kms_stdout.log", "r") as f:
            print(f.read())

if __name__ == "__main__":
    test_integration()
