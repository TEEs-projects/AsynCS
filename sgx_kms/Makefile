# SGX SDK Settings
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

# Output files
App_Name := sgx_kms
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so

# Trusted MCL settings for in-enclave BF-IBE Extract/key release.
TRUSTED_MCL_PREFIX ?= $(abspath ../_tmp/trusted-mcl)
Enclave_MCL_Defines := -DMCL_FP_BIT=384 -DMCL_FR_BIT=256 \
                       -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_CSPRNG \
                       -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING \
                       -DMCL_BINT_ASM=0 -DMCL_MSM=0 -DNDEBUG

# App Settings
App_Cpp_Files := App/App.cpp
App_Include_Paths := -IApp -I$(SGX_SDK)/include

App_C_Flags := $(App_Include_Paths) -fPIC -Wno-attributes
App_Cxx_Flags := $(App_C_Flags) -std=c++11

# Enclave Settings
Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_Include_Paths := -IEnclave -I../trusted -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(TRUSTED_MCL_PREFIX)/include

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -fstack-protector -fno-builtin-printf -I. $(Enclave_MCL_Defines)
Enclave_Cxx_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++ -fno-exceptions -fno-rtti -fno-threadsafe-statics

ifneq ($(SGX_MODE), HW)
App_Cxx_Flags += -DSGX_MODE_SIM
App_Link_Flags := -Llib -L$(SGX_SDK)/lib64 -lsgx_urts_sim -lpthread -lcrypto -lsgx_dcap_ql -lsgx_dcap_quoteverify -lsgx_uae_service_sim
Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -z noexecstack -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_pthread -lsgx_tservice -lsgx_tcrypto -L$(TRUSTED_MCL_PREFIX)/lib -lmcl_trusted -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -L$(SGX_SDK)/lib64
else
App_Link_Flags := -Llib -L$(SGX_SDK)/lib64 -lsgx_urts -lpthread -lcrypto -lsgx_dcap_ql -lsgx_dcap_quoteverify -lsgx_uae_service
Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -z noexecstack -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_pthread -lsgx_tservice -lsgx_tcrypto -L$(TRUSTED_MCL_PREFIX)/lib -lmcl_trusted -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -L$(SGX_SDK)/lib64
endif

.PHONY: all clean

all: $(App_Name) $(Signed_Enclave_Name)

clean:
	rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) App/*.o App/Enclave_u.* Enclave/*.o Enclave/Enclave_t.* Enclave/*.pem Enclave/*.xml

$(App_Name): App/Enclave_u.o App/App.o
	$(CXX) $^ -o $@ $(App_Link_Flags)

App/Enclave_u.c: $(SGX_SDK)/bin/x64/sgx_edger8r Enclave/Enclave.edl
	cd App && $(SGX_SDK)/bin/x64/sgx_edger8r --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include

App/Enclave_u.o: App/Enclave_u.c
	$(CC) $(App_C_Flags) -c $< -o $@

App/App.o: App/App.cpp App/Enclave_u.c
	$(CXX) $(App_Cxx_Flags) -c $< -o $@

Enclave/Enclave_t.c: $(SGX_SDK)/bin/x64/sgx_edger8r Enclave/Enclave.edl
	cd Enclave && $(SGX_SDK)/bin/x64/sgx_edger8r --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@

Enclave/Enclave.o: Enclave/Enclave.cpp Enclave/Enclave_t.c
	$(CXX) $(Enclave_Cxx_Flags) -c $< -o $@

Enclave/bfibe_mcl.o: ../trusted/bfibe_mcl.cpp ../trusted/bfibe_mcl.h
	$(CXX) $(Enclave_Cxx_Flags) -c $< -o $@

$(Enclave_Name): Enclave/Enclave_t.o Enclave/Enclave.o Enclave/bfibe_mcl.o
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave_Name): $(Enclave_Name)
	openssl genrsa -out Enclave/Enclave_private.pem -3 3072 2>/dev/null
	echo '<EnclaveConfiguration><ProdID>0</ProdID><ISVSVN>0</ISVSVN><StackMaxSize>0x40000</StackMaxSize><HeapMaxSize>0x4000000</HeapMaxSize><TCSNum>10</TCSNum><TCSPolicy>1</TCSPolicy><DisableDebug>0</DisableDebug><MiscSelect>0</MiscSelect><MiscMask>0xFFFFFFFF</MiscMask></EnclaveConfiguration>' > Enclave/Enclave.config.xml
	$(SGX_SDK)/bin/x64/sgx_sign sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config Enclave/Enclave.config.xml
