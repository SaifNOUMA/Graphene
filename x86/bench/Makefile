
CC=gcc
CC_FLAGS= -march=native -O3
CC_LIBS= -lssl -lcrypto -ltomcrypt -lgmp -lgcrypt
INC_DIR= -I.. -I../prf -I../umac  -I../poly1305/poly1305aes
OBJ_DIR = .

all: bench_poly1305 bench_hash bench_hmac bench_umac_lc bench_umac_sqh bench_umac_lc_intel bench_prf bench_aes_ni bench_xor bench_lcmac bench_sqmac

AESNI_SRC_FILES=aesni.c
XOR_SRC_FILES=xor.c ../umac/common.c
HASH_SRC_FILES=hash.c ../umac/common.c
HMAC_SRC_FILES=hmac.c ../umac/common.c
PRF_SRC_FILES=prf.c ../umac/common.c
POLY1305_SRC_FILES=poly1305.c ../prf/rng_byte.c ../prf/prf.c ../umac/common.c ../poly1305/poly1305aes/poly1305aes.a
CHACHAPOLY1305_SRC_FILES=chacha_poly1305.c ../umac/common.c
UMAC_LC_INTEL_SRC_FILES=umac_lc_intel.c ../umac/common.c 
BPMAC_SRC_FILES=bpmac.c ../umac/common.c
SQMAC_SRC_FILES=sqmac.c ../umac/sq_umac.c ../umac/common.c ../prf/prf.c ../prf/rng.c
LCMAC_SRC_FILES=lcmac.c ../umac/lc_umac.c ../umac/common.c ../prf/prf.c ../prf/rng.c

UMAC_LC_SRC_FILES=umac_lc.c ../umac/lc_umac.c ../umac/common.c ../prf/prf.c  ../prf/rng.c
UMAC_SQH_SRC_FILES=umac_sq.c ../umac/sq_umac.c ../umac/common.c ../prf/prf.c  ../prf/rng.c

bench_hash:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(HASH_SRC_FILES) $(CC_LIBS)

bench_xor:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(XOR_SRC_FILES) $(CC_LIBS)

bench_hmac:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(HMAC_SRC_FILES) $(CC_LIBS)

bench_prf:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(PRF_SRC_FILES) $(CC_LIBS)

bench_bpmac:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(BPMAC_SRC_FILES) $(CC_LIBS)

bench_poly1305:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(POLY1305_SRC_FILES) $(CC_LIBS) 

bench_chacha_poly1305:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(CHACHAPOLY1305_SRC_FILES) $(CC_LIBS) 

bench_umac_lc:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(UMAC_LC_SRC_FILES) $(CC_LIBS)

bench_lcmac:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(LCMAC_SRC_FILES) $(CC_LIBS)

bench_sqmac:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(SQMAC_SRC_FILES) $(CC_LIBS)

bench_umac_lc_intel:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(UMAC_LC_INTEL_SRC_FILES) $(CC_LIBS)

bench_umac_sqh:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(UMAC_SQH_SRC_FILES) $(CC_LIBS)

bench_aes_ni:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(AESNI_SRC_FILES) $(CC_LIBS)

clean:
	rm -f $(OBJ_DIR)/bench_*
