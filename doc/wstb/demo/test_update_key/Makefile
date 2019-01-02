CC=cc
CCP=gcc

INCLUDEDIR = -I./ -I../include

CC=gcc
CCP=g++

DEBUG_FLAGS = -ggdb3 -D__linux__ -D_DEBUG
RELEASE_FLAGS = -O2 -D__linux__
#Debug
CFLAGS= -Wall -Wno-long-long -fexceptions $(DEBUG_FLAGS) $(INCLUDEDIR)

#Release
#CFLAGS= $(RELEASE_FLAGS) $(INCLUDEDIR) -L/usr/lib
LIBS=/usr/lib64/libpthread.so
LIBS+=/usr/lib64/libdl.so
SOURCE1 = ./
SOURCE2 = ../include/
APPS  = ../bin/demo_update_key
OBJS  = base64.o api_dll50.o PlateformDefine.o test_update_key.o

all: $(APPS)

test_update_key.o:$(SOURCE1)test_update_key.c
	$(CC) -c $(CFLAGS) $(SOURCE1)test_update_key.c

api_dll50.o:$(SOURCE2)api_dll50.c
	$(CC) -c $(CFLAGS) $(SOURCE2)api_dll50.c

base64.o:$(SOURCE2)base64.c
	$(CC) -c $(CFLAGS) $(SOURCE2)base64.c

PlateformDefine.o:$(SOURCE2)PlateformDefine.c
	$(CC) -c $(CFLAGS) $(SOURCE2)PlateformDefine.c

$(APPS):$(OBJS) $(LIBS)
	$(CC)  $(CFLAGS)  -o  $(APPS) $(OBJS) $(LIBS)

clean:
	rm  -f *.o *~ *.bak $(APPS)


