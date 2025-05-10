
CC=gcc
CC_FLAGS= -march=native -O3
CC_LIBS= -lssl -lcrypto -ltomcrypt -lgmp -lgcrypt
INC_DIR= -I.. -I../prf -I../umac
OBJ_DIR = .

all: fae graphene_gcm graphene_lc graphene_poly1305

FAE_SRC_FILES=hash.c hmac.c fae.c main.c
GRAPHENE_GCM_SRC_FILES=graphenegcm.c
GRAPHENE_LC_SRC_FILES=graphenelc.c ../prf/rng.c ../prf/prf.c ../umac/lc_umac.c ../umac/common.c
GRAPHENE_POLY1305_SRC_FILES=graphenepoly.c

fae:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(FAE_SRC_FILES) $(CC_LIBS)

graphene_gcm:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(GRAPHENE_GCM_SRC_FILES) $(CC_LIBS)

graphene_lc:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(GRAPHENE_LC_SRC_FILES) $(CC_LIBS)

graphene_poly1305:
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(GRAPHENE_POLY1305_SRC_FILES) $(CC_LIBS)
	
clean:
	rm -f $(OBJ_DIR)/fae $(OBJ_DIR)/graphene_gcm $(OBJ_DIR)/graphene_lc $(OBJ_DIR)/graphene_poly1305
