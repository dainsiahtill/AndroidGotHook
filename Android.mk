LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:=\
	src/main.c \
	src/elf_helper.c \
	src/remote.c \
	src/inject.c \
	src/ptrace.c \
	src/utils.c \

LOCAL_CFLAGS := -std=c99 -Wformat
LOCAL_CFLAGS += -DDEBUG
LOCAL_SHARED_LIBRARIES += \
			libdl

LOCAL_LDLIBS += \
			-ldl \

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/include

LOCAL_MODULE_TAGS := eng

LOCAL_MODULE := got

include $(BUILD_EXECUTABLE)
