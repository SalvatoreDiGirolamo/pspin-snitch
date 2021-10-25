TARGET_SLM ?= ${PSPIN_HW}/sim_files/slm_files
TARGET_VSIM ?= ${PSPIN_HW}/${PSPIN_SIM}
S19TOSLM ?= ${PSPIN_RT}/scripts/s19toslm.py
SPIN_APP_NAME ?= ""
TRACE_DIR ?= ""
INFO_KEY ?= ""

CC=${RISCV_GCC}/riscv32-unknown-elf-gcc
OBJCOPY=${RISCV_GCC}/riscv32-unknown-elf-objcopy
OBJDUMP=${RISCV_GCC}/riscv32-unknown-elf-objdump
TARGET_BIN=build/$(SPIN_APP_NAME)

LIBS_SRC=$(PSPIN_RT)/runtime/src/io.c 
LIBS_INCLUDE=$(PSPIN_RT)/runtime/vendor/
INCLUDE_FILES=-I${PSPIN_RT}/runtime/include/ -I${LIBS_INCLUDE}
SRC_FILES=${PSPIN_RT}/runtime/src/hpu.c ${SPIN_APP_SRCS} ${LIBS_SRC}
CFLAGS=-O3 -march=rv32imafdXpspin -mabi=ilp32d -mcmodel=medany -mno-fdiv -ffast-math -fno-builtin-printf -fno-common -ffunction-sections -flto
LDFLAGS=-nostartfiles -nostdlib -Wl,--gc-sections -T ${PSPIN_RT}/linker/link.ld -lm -lgcc

deploy::
	mkdir -p build/
	$(CC) $(CFLAGS) -DLANGUAGE_ASSEMBLY $(INCLUDE_FILES) -c $(PSPIN_RT)/boot/start.S -o build/start.o
	$(CC) $(CFLAGS) ${SPIN_CFLAGS} $(PULP_INC) $(INCLUDE_FILES) build/start.o $(SRC_FILES) -o $(TARGET_BIN) $(LDFLAGS)
	mkdir -p build/slm_files/
	$(OBJCOPY) --srec-len 1 --output-target=srec $(TARGET_BIN) build/$(SPIN_APP_NAME).s19
	cd build/slm_files && \
	$(S19TOSLM) ../$(SPIN_APP_NAME).s19 && \
	cd ../../ && \
	$(OBJDUMP) -S build/$(SPIN_APP_NAME) > build/$(SPIN_APP_NAME).disasm

trace-chrome::
	@python3 $(PSPIN_RT)/scripts/tracer.py -e build/$(SPIN_APP_NAME) -d build/$(SPIN_APP_NAME).disasm logs/trace_hart_* > $(SPIN_APP_NAME).trace.json

trace::
	@python3 $(PSPIN_RT)/scripts/tracer.py -e build/$(SPIN_APP_NAME) -d build/$(SPIN_APP_NAME).disasm -x logs/trace_hart_* > $(SPIN_APP_NAME).trace.txt
	
info::
	make trace;
	$(PSPIN_RT)/scripts/handlers_info.sh $(INFO_KEY) $(SPIN_APP_NAME).trace.txt

stats::
	$(PSPIN_RT)/scripts/handlers_duration.sh transcript
