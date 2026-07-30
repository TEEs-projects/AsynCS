# SGX SDK Settings
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

# sgx_edger8r writes paired generated files (Enclave_u.c/.h and
# Enclave_t.c/.h). GNU Make 4.2 can run such multi-target rules twice under
# -j, which races and can leave inconsistent glue.
.NOTPARALLEL:

# WAMR Settings
WAMR_ROOT ?= $(abspath ../../wasm-micro-runtime)
WAMR_SGX_BUILD := $(WAMR_ROOT)/product-mini/platforms/linux-sgx/build

# Trusted MCL settings for in-enclave BF-IBE smoke/integration.
TRUSTED_MCL_PREFIX ?= $(abspath ../_tmp/trusted-mcl)
Enclave_MCL_Defines := -DMCL_FP_BIT=384 -DMCL_FR_BIT=256 \
                       -DMCL_DONT_USE_XBYAK -DMCL_DONT_USE_CSPRNG \
                       -DCYBOZU_DONT_USE_EXCEPTION -DCYBOZU_DONT_USE_STRING \
                       -DMCL_BINT_ASM=0 -DMCL_MSM=0 -DNDEBUG

# Output files
App_Name := sgx_worker
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so

# App Settings
App_Cpp_Files := App/App.cpp App/app_ibe.cpp
App_Include_Paths := -IApp -I$(SGX_SDK)/include -I/usr/include/node

App_C_Flags := $(App_Include_Paths) -fPIC -Wno-attributes
App_Cxx_Flags := $(App_C_Flags) -std=c++11

ifneq ($(SGX_MODE), HW)
Urts_Library_Name := sgx_urts_sim
Trts_Library_Name := sgx_trts_sim
Service_Library_Name := sgx_uae_service_sim
DCAP_Library_Flag :=
App_Cxx_Flags += -DSGX_MODE_SIM
else
Urts_Library_Name := sgx_urts
Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_uae_service
DCAP_Library_Flag := -lsgx_dcap_ql
endif

# App Link Flags
App_Link_Flags := -Llib -L$(SGX_SDK)/lib64 -l$(Urts_Library_Name) -lpthread -L$(WAMR_SGX_BUILD) -lvmlib_untrusted -lcrypto $(DCAP_Library_Flag) -l$(Service_Library_Name)

# Enclave Settings
Enclave_Cpp_Files := Enclave/Enclave.cpp Enclave/mcl_ibe.cpp
Enclave_Include_Paths := -IEnclave -I../trusted -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
                         -I$(SGX_SDK)/include/libcxx \
                         -I$(WAMR_ROOT)/core/iwasm/include \
                         -I$(WAMR_ROOT)/core/iwasm/common \
                         -I$(WAMR_ROOT)/core/shared/utils \
                         -I$(WAMR_ROOT)/core/shared/platform/linux-sgx \
                         -I$(TRUSTED_MCL_PREFIX)/include

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -fstack-protector \
                   -fno-builtin-printf -I. $(Enclave_MCL_Defines)
Enclave_Cxx_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++ -fno-exceptions -fno-rtti -fno-threadsafe-statics

Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -z noexecstack \
                      -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
                      -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_pthread -lsgx_tservice -lsgx_tcrypto -L$(WAMR_SGX_BUILD) -lvmlib -L$(TRUSTED_MCL_PREFIX)/lib -lmcl_trusted -Wl,--end-group \
                      -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                      -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
                      -Wl,--defsym,__ImageBase=0 \
                      -L$(SGX_SDK)/lib64

.PHONY: all clean FORCE

all: $(App_Name) $(Signed_Enclave_Name)

# App Objects
App/Enclave_u.c App/Enclave_u.h: FORCE $(SGX_SDK)/bin/x64/sgx_edger8r Enclave/Enclave.edl
	cd App && $(SGX_SDK)/bin/x64/sgx_edger8r --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include --search-path $(WAMR_ROOT)/core/shared/platform/linux-sgx

App/Enclave_u.o: App/Enclave_u.c
	$(CC) $(App_C_Flags) -c $< -o $@

App/App.o: App/App.cpp App/Enclave_u.h
	$(CXX) $(App_Cxx_Flags) -c $< -o $@

App/app_ibe.o: App/app_ibe.cpp App/app_ibe.h App/Enclave_u.h
	$(CXX) $(App_Cxx_Flags) -c $< -o $@

$(App_Name): App/Enclave_u.o App/App.o App/app_ibe.o
	$(CXX) $^ -o $@ $(App_Link_Flags)

# Enclave Objects
Enclave/Enclave_t.c Enclave/Enclave_t.h: FORCE $(SGX_SDK)/bin/x64/sgx_edger8r Enclave/Enclave.edl
	cd Enclave && $(SGX_SDK)/bin/x64/sgx_edger8r --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include --search-path $(WAMR_ROOT)/core/shared/platform/linux-sgx

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@

Enclave/Enclave.o: Enclave/Enclave.cpp Enclave/Enclave_t.h
	$(CXX) $(Enclave_Cxx_Flags) -c $< -o $@

Enclave/mcl_ibe.o: Enclave/mcl_ibe.cpp Enclave/mcl_ibe.h ../trusted/bfibe_mcl.h Enclave/Enclave_t.h
	$(CXX) $(Enclave_Cxx_Flags) -c $< -o $@

Enclave/bfibe_mcl.o: ../trusted/bfibe_mcl.cpp ../trusted/bfibe_mcl.h
	$(CXX) $(Enclave_Cxx_Flags) -c $< -o $@

$(Enclave_Name): Enclave/Enclave_t.o Enclave/Enclave.o Enclave/mcl_ibe.o Enclave/bfibe_mcl.o
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave_Name): $(Enclave_Name) Enclave/Enclave_private.pem Enclave/Enclave.config.xml
	$(SGX_SDK)/bin/x64/sgx_sign sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config Enclave/Enclave.config.xml

Enclave/Enclave_private.pem:
	openssl genrsa -out $@ -3 3072

Enclave/Enclave.config.xml:
	echo '<EnclaveConfiguration><ProdID>0</ProdID><ISVSVN>0</ISVSVN><StackMaxSize>0x40000</StackMaxSize><HeapMaxSize>0x4000000</HeapMaxSize><ReservedMemMaxSize>0x4000000</ReservedMemMaxSize><ReservedMemExecutable>1</ReservedMemExecutable><TCSNum>10</TCSNum><TCSPolicy>1</TCSPolicy><DisableDebug>0</DisableDebug><MiscSelect>0</MiscSelect><MiscMask>0xFFFFFFFF</MiscMask></EnclaveConfiguration>' > $@

clean:
	rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) App/*.o App/Enclave_u.* Enclave/*.o Enclave/Enclave_t.* Enclave/*.pem Enclave/*.xml
