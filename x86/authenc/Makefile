
CC=gcc
CC_FLAGS= 
CC_LIBS= -lssl -lcrypto
INC_DIR= -I..
OBJ_DIR = ./bin

OBJS=$(OBJ_DIR)/hash.o $(OBJ_DIR)/hmac.o $(OBJ_DIR)/fae.o $(OBJ_DIR)/main.o 

run_test: $(OBJS)
	$(CC) $(CC_FLAGS) $(INC_DIR) -o $(OBJ_DIR)/$@ $(OBJS) $(CC_LIBS)

$(OBJ_DIR)/%.o: %.c
	$(CC) $(CC_FLAGS) $(INC_DIR) -c $< -o $@

clean:
	rm -f $(OBJ_DIR)/*.o $(OBJ_DIR)/run_test