import socket
import struct
import sys

def start_server(port=3000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('all-interfaces', port))
    server_socket.listen(1)
    print(f"Mock KMS listening on port {port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        
        try:
            # 1. Read Quote Size
            data = client_socket.recv(4)
            if not data: break
            quote_size = struct.unpack('<I', data)[0]
            print(f"Quote Size: {quote_size}")
            
            # 2. Read Quote
            quote = b''
            while len(quote) < quote_size:
                chunk = client_socket.recv(quote_size - len(quote))
                if not chunk: break
                quote += chunk
            print(f"Received Quote ({len(quote)} bytes)")
            
            # 3. Read FID Len
            data = client_socket.recv(4)
            fid_len = struct.unpack('<I', data)[0]
            
            # 4. Read FID
            fid = client_socket.recv(fid_len).decode('utf-8')
            print(f"FID: {fid}")
            
            # 5. Read Label Len
            data = client_socket.recv(4)
            label_len = struct.unpack('<I', data)[0]
            
            # 6. Read Label
            label = client_socket.recv(label_len).decode('utf-8')
            print(f"Label: {label}")
            
            # 7. Read Public Key
            pub_key = client_socket.recv(64)
            print(f"Public Key received")
            
            # 8. Send Key (32 bytes)
            # Hardcoded key: 32 bytes of 0x01
            key = b'\x01' * 32
            client_socket.send(key)
            print("Sent Key")
            
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

if __name__ == '__main__':
    start_server()
