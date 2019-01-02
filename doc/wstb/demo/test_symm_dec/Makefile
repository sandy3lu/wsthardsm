CC=gcc
CCP=g++

INCLUDEDIR = -I./ -I../include

LIBS=/usr/lib64/libdl.so
LIBS+=/usr/lib64/libpthread.so 
#DEBUG_FLAGS = -ggdb3 -D__linux__ -D_DEBUG
#RELEASE_FLAGS = -O2 -D__linux__
DEBUG_FLAGS = -ggdb3 -D__linux__ -D_DEBUG
RELEASE_FLAGS = -O2 -D__linux__
#Debug
#CFLAGS= -Wall -Wno-long-long -fexceptions $(DEBUG_FLAGS) $(INCLUDEDIR)

#Release
CFLAGS=  -Wall -Wno-long-long -fexceptions $(RELEASE_FLAGS) $(INCLUDEDIR)

SOURCE1 = ./
SOURCE2 = ../include/
APPS  = ../bin/test_sym_dec_lnx
OBJS  = api_dll50.o PlateformDefine.o test_sym_dec.o  

all: $(APPS)

test_basic.o:$(SOURCE1)test_sym_dec.c
	$(CC) -c $(CFLAGS) $(SOURCE1)test_sym_dec.c

api_dll50.o:$(SOURCE2)api_dll50.c
	$(CC) -c $(CFLAGS) $(SOURCE2)api_dll50.c

PlateformDefine.o:$(SOURCE2)PlateformDefine.c
	$(CC) -c $(CFLAGS) $(SOURCE2)PlateformDefine.c

$(APPS):$(OBJS) $(LIBS)
	$(CC)  $(CFLAGS)  -o  $(APPS) $(OBJS) $(LIBS)

clean:
	rm  -f *.o *~ *.bak $(APPS)


