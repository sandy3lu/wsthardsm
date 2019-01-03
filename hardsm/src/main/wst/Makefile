LIB_DIR ?= ../resources


# --- configs ---
mock_mode ?= 1
CC = gcc


# --- file lists ---
OUT_DIR = build
TARGET_DIR = $(OUT_DIR)/target

SM_SRC = $(wildcard sm/*.c)
PROTO_SRC = $(wildcard proto/*.c)
UTIL_SRC = $(wildcard util/*.c)
SOURCE = $(PROTO_SRC) $(SM_SRC) $(UTIL_SRC)
SMTEST_SRC = $(wildcard test/smtest/*.c)
SMTOOL_SRC = $(wildcard test/smtool/*.c)

PROTO_OBJ = $(subst proto/, $(OUT_DIR)/, $(addsuffix .o, $(basename $(PROTO_SRC))))
SM_OBJ = $(subst sm/, $(OUT_DIR)/, $(addsuffix .o, $(basename $(SM_SRC))))
UTIL_OBJ = $(subst util/, $(OUT_DIR)/, $(addsuffix .o, $(basename $(UTIL_SRC))))
OBJ = $(PROTO_OBJ) $(SM_OBJ) $(UTIL_OBJ)
SMTEST_OBJ = $(subst test/smtest, $(OUT_DIR)/, $(addsuffix .o, $(basename $(SMTEST_SRC))))
SMTOOL_OBJ = $(subst test/smtool, $(OUT_DIR)/, $(addsuffix .o, $(basename $(SMTOOL_SRC))))

# --- target ---
YJSMWST_LIB = $(TARGET_DIR)/libyjsmwst.so
SM_TOOL = $(TARGET_DIR)/smtool
SM_TEST = $(TARGET_DIR)/smtest

# --- commands ---
MKDIR_CMD = mkdir -p $@
CC_CMD = $(CC) -c -Wall -fPIC -DMOCK_MODE=$(mock_mode) -o $@ $<


# --- build libyjsmwst.so ---
$(YJSMWST_LIB) : $(SM_OBJ) $(PROTO_OBJ) $(UTIL_OBJ) | $(TARGET_DIR)
	$(CC) -o $@ $^ -shared $(LIB_DIR)/libsmwst.so
	cp $(YJSMWST_LIB) $(LIB_DIR)/

$(OUT_DIR)/%.o : util/%.c | $(OUT_DIR)
	$(CC_CMD)

$(OUT_DIR)/%.o : proto/%.c | $(OUT_DIR)
	$(CC_CMD)

$(OUT_DIR)/%.o : sm/%.c | $(OUT_DIR)
	$(CC_CMD)

$(OUT_DIR) $(TARGET_DIR):
	$(MKDIR_CMD)


# --- demo ---
demo: smtest smtool

smtest : $(SMTEST_OBJ) $(LIB_DIR)/libyjsmwst.so $(LIB_DIR)/libsmwst.so | $(TARGET_DIR)
	$(CC) -o $(SM_TEST) $^
	cp $(SM_TEST) $(LIB_DIR)

smtool : $(SMTOOL_OBJ) $(LIB_DIR)/libyjsmwst.so $(LIB_DIR)/libsmwst.so | $(TARGET_DIR)
	$(CC) -o $(SM_TOOL) $^
	cp $(SM_TOOL) $(LIB_DIR)

$(OUT_DIR)/%.o : test/smtest/%.c | $(OUT_DIR)
	$(CC) -c -Wall -o $@ $<

$(OUT_DIR)/%.o : test/smtool/%.c | $(OUT_DIR)
	$(CC) -c -Wall -o $@ $<


update-protoc:
	cd proto && protoc-c --c_out=. sm.proto
	cd proto && sed 's/<protobuf-c\/protobuf-c.h>/"protobuf-c.h"/g' sm.pb-c.h >sm.pb-c.h.tmp
	cd proto && mv sm.pb-c.h.tmp sm.pb-c.h

clean:
	- rm -rf build
