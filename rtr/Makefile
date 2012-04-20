#
#	Makefile for lispd
#
#
#
#	David Meyer
#	dmm@1-4-5.net
#	Mon Apr 19 11:40:19 2010
#
#	$Header: /home/dmm/lisp/lispd/RCS/Makefile,v 1.2 2010/04/19 22:02:33 dmm Exp $
#

# modified by arnatal

CC		= gcc
GENGETOPT	= gengetopt
CFLAGS		+= -Wall -Wno-implicit-function-declaration -g -DDEBUG=3 -I../lispd/ 
LIBS		= -lconfuse -lssl -lcrypto -lrt
INC		= lispd.h
MAKEFILE	= Makefile
VPATH = ../lispd 
OBJS		= cmdline.o lispd_config.o lispd_syslog.o	\
		  lispd_lib.o lispd_ipc.o lispd_map_register.o		\
		  patricia/patricia.o lispd_map_request.o cksum.o lispd_map_notify.o \
		  lispd_patricia.o lispd_map_reply.o lispd_iface_mgmt.o	\
		  lispd_iface_list.o lispd_info_request.o lispd_info_reply.o lispd_nat_lib.o lispd_info_nat.o \
		  rtr_lib.o

EXE1	= RTR_dummy_client 
EXE2    = RTR_dummy_server

OBJ1	= RTR_dummy_client.o
OBJ2    = RTR_dummy_server.o

PREFIX		= /usr/local/sbin



$(EXE1): $(OBJS) $(OBJ1)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(EXE2): $(OBJS) $(OBJ2)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

#
#	gengetops generates this...
#
cmdline.c: lispd.ggo
	$(GENGETOPT) -i $<

%.o: %.c $(DEPS) $(INC) $(MAKEFILE)
	$(CC) -c -o $@ $< $(CFLAGS)

all:
	make $(EXE)

clean:
	rm -f *.o $(EXE) patricia/*.o cscope.out

distclean: clean
	rm -f cmdline.[ch]

install: $(EXE)
	mkdir -p $(PREFIX) && cp $(EXE) $(PREFIX)

tags:
	cscope -R -b
