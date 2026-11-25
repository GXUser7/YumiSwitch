.SUFFIXES:

ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment.")
endif

TOPDIR ?= $(CURDIR)
include $(DEVKITPRO)/libnx/switch_rules

APP_TITLE   := Yumi NX
APP_AUTHOR  := YumiSwitch
APP_VERSION := 1.0.0
APP_TITLEID := 4200000000079802

TARGET      := yumi
BUILD       := build
ROMFS       := romfs
NO_ICON     := 1

SOURCES     := source/ui \
               source/logic \
               source/platform/switch \
               ../common/src \
               ../core-net/src \
               ../third_party/nanovg/src \
               ../third_party/yoga/yoga \
               ../third_party/yoga/yoga/algorithm \
               ../third_party/yoga/yoga/config \
               ../third_party/yoga/yoga/debug \
               ../third_party/yoga/yoga/event \
               ../third_party/yoga/yoga/node

INCLUDES    := source/ui \
               source/logic \
               source/platform/switch \
               ../common/include \
               ../core-net/include \
               ../third_party \
               ../third_party/nanovg/src \
               ../third_party/yoga

ARCH        := -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE
CFLAGS      := -g -Wall -O2 -ffunction-sections -fdata-sections $(ARCH) $(DEFINES) $(INCLUDE) -D__SWITCH__
CXXFLAGS    := $(CFLAGS) -fno-exceptions -std=c++20
ASFLAGS     := -g $(ARCH)
LDFLAGS     := -specs=$(DEVKITPRO)/libnx/switch.specs -g $(ARCH) -Wl,-Map,$(notdir $*.map) -Wl,--gc-sections
LIBS        := -lglad -lEGL -lglapi -ldrm_nouveau -lnx -lm
LIBDIRS     := $(PORTLIBS) $(LIBNX)

ifneq ($(BUILD),$(notdir $(CURDIR)))

export OUTPUT  := $(CURDIR)/$(TARGET)
export TOPDIR  := $(CURDIR)
export VPATH   := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR := $(CURDIR)/$(BUILD)

CFILES   := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES   := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))

export LD := $(CXX)
export OFILES_SRC := $(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)
export OFILES     := $(OFILES_SRC)

export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
                  $(foreach dir,$(LIBDIRS),-I$(dir)/include) \
                  -I$(CURDIR)/$(BUILD)

export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

export NROFLAGS += --nacp=$(CURDIR)/$(TARGET).nacp --romfsdir=$(CURDIR)/$(ROMFS)
export NACPFLAGS += --titleid=$(APP_TITLEID)

.PHONY: $(BUILD) clean all
all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

clean:
	@rm -fr $(BUILD) $(TARGET).nro $(TARGET).nacp $(TARGET).elf

else

.PHONY: all
DEPENDS := $(OFILES:.o=.d)

all: $(OUTPUT).nro

$(OUTPUT).nro: $(OUTPUT).elf $(OUTPUT).nacp
	@elf2nro $< $@ $(NROFLAGS)
	@echo "built ... $(notdir $@)"

$(OUTPUT).elf: $(OFILES)

-include $(DEPENDS)

endif
