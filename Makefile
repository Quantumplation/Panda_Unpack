PLUGIN_NAME=unpack

# Include the PANDA Makefile rules
include ../panda.mak

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o
	$(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so
