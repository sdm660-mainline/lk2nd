LOCAL_DIR := $(GET_LOCAL_DIR)

ARCH    := arm
ARM_CPU := cortex-a8
CPU     := generic

DEFINES += ARM_CPU_CORE_KRYO

MMC_SLOT := 1

# DEFINES += PERIPH_BLK_BLSP=1 # nope
DEFINES += WITH_CPU_EARLY_INIT=0 WITH_CPU_WARM_BOOT=0 \
	   MMC_SLOT=$(MMC_SLOT) \
	   WITH_UART_DM_EARLY=1 UARTM_DM_EARLY_BASE=0xC170000

INCLUDES += -I$(LOCAL_DIR)/include -I$(LK_TOP_DIR)/platform/msm_shared/include

DEVS += fbcon
MODULES += dev/fbcon

OBJS += \
	$(LOCAL_DIR)/sdm660-acpuclock.o \
	$(LOCAL_DIR)/sdm660-clock.o \
	$(LOCAL_DIR)/sdm660-platform.o \
	$(LOCAL_DIR)/sdm660-gpio.o

LINKER_SCRIPT += $(BUILDDIR)/system-onesegment.ld

include platform/msm_shared/rules.mk
