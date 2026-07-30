SGX_SDK := /opt/intel/sgxsdk
SGX_MODE ?= HW

ifeq ($(SGX_MODE), HW)
TRTS := sgx_trts
SERVICE := sgx_tservice
URTS := sgx_urts
else
TRTS := sgx_trts_sim
SERVICE := sgx_tservice_sim
URTS := sgx_urts_sim
endif

all: test_app test.signed.so

test_t.c test_t.h: test.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --trusted test.edl --search-path $(SGX_SDK)/include

test_u.c test_u.h: test.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --untrusted test.edl --search-path $(SGX_SDK)/include

test_t.o: test_t.c
	gcc -c $< -o $@ -nostdinc -I$(SGX_SDK)/include -include sgx_report.h -I$(SGX_SDK)/include/tlibc -fPIC -fvisibility=hidden -fpie -fstack-protector

test_enclave.o: test_enclave.cpp test_t.h
	g++ -c $< -o $@ -nostdinc -I$(SGX_SDK)/include -include sgx_report.h -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -fPIC -fvisibility=hidden -fpie -fstack-protector -std=c++11 -nostdinc++

test.so: test_t.o test_enclave.o
	g++ -o $@ $^ -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_SDK)/lib64 -Wl,--whole-archive -l$(TRTS) -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(SERVICE) -lsgx_tcrypto -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0

test.signed.so: test.so
	openssl genrsa -out private.pem -3 3072 2>/dev/null
	$(SGX_SDK)/bin/x64/sgx_sign sign -key private.pem -enclave test.so -out $@ -config /opt/intel/SGXDataCenterAttestationPrimitives/SampleCode/QuoteGenerationSample/Enclave/Enclave.config.xml

test_u.o: test_u.c
	gcc -c $< -o $@ -I$(SGX_SDK)/include -include sgx_report.h -fPIC

test_app.o: test_app.cpp test_u.h
	g++ -c $< -o $@ -I$(SGX_SDK)/include -include sgx_report.h -std=c++11

test_app: test_u.o test_app.o
	g++ -o $@ $^ -L$(SGX_SDK)/lib64 -l$(URTS) -lpthread

clean:
	rm -f *.o test_t.* test_u.* test.so test.signed.so test_app private.pem
