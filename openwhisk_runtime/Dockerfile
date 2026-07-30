FROM ubuntu:22.04

# Install Python and dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libssl-dev \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install flask

WORKDIR /app

# Copy SGX libs
COPY libs /app/libs
ENV LD_LIBRARY_PATH=/app/libs

# Copy Worker and Enclave
COPY sgx_worker /app/sgx_worker
COPY enclave.signed.so /app/enclave.signed.so

# Copy Proxy
COPY proxy.py /app/proxy.py

# Set permissions
RUN chmod +x /app/sgx_worker

# Expose port
EXPOSE 8080

# Run proxy
CMD ["python3", "proxy.py"]
