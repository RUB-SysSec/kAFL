OBJECTS = Driver.o
TARGET = Driver.sys
CFLAGS = -I /usr/x86_64-w64-mingw32/include/ddk -I /usr/x86_64-w64-mingw32/include -DMINGW -std=c99 -Wall -m64 -shared
CROSS_PREFIX = x86_64-w64-mingw32-

all: $(TARGET)
clean:
	rm -f Driver.o $(TARGET)
%.o: %.c
	$(CROSS_PREFIX)gcc $(CFLAGS) -c $< -o $@

$(TARGET): Driver.o
	$(CROSS_PREFIX)gcc $(CFLAGS) -Wl,--subsystem,native -Wl,--image-base,0x10000 \
	-Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 \
	-Wl,--entry,DriverEntry@8 -Wl,--stack,0x40000 -Wl,--dynamicbase -Wl,--nxcompat \
	-nostartfiles -nostdlib -o $(TARGET) \
	$(OBJECTS) -lntoskrnl -lhal
