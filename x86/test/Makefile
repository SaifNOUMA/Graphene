
CC=gcc
CC_FLAGS= 
CC_LIBS= -lssl -lcrypto -lgcrypt -ltomcrypt -lgmp
INC_DIR= -I..  -I../poly1305/poly1305aes
OBJ_DIR = .

all: test_poly1305 test_hash test_prf

POLY1305_FILES=poly1305.c ../poly1305/poly1305aes/poly1305aes.a
HASH_SRC_FILES=hash.c  ../umac/common.c ../prf/prf.c
PRF_SRC_FILES=prf.c  ../umac/common.c ../prf/prf.c

test_poly1305:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(POLY1305_FILES) $(CC_LIBS) 

test_hash:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(HASH_SRC_FILES) $(CC_LIBS)

test_prf:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(PRF_SRC_FILES) $(CC_LIBS)

clean:
	rm -f $(OBJ_DIR)/test_poly1305 $(OBJ_DIR)/test_hash $(OBJ_DIR)/test_prf
