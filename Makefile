CC	= gcc
CXX	= g++
CFLAGS	= -Wall -g
LDFLAGS	=


ASM64  = yasm -f elf64 -DYASM -D__x86_64__
#ASM64 = nasm -f elf64 -DNASM -D__x86_64__


PROGS  = hw4 

all: $(PROGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<

%.o: %.asm
	$(ASM64) $< -o $@

hw4: hw4.o ptools.o command.o
	$(CXX) -o $@ $^ $(LDFLAGS) -l capstone 


%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o *~ $(PROGS)
	make -C tests clean
