###############################################
#
#  kavsprayvpn - spray packet for VPN connection
#                to prevent traffic analysis by DPI
#
#  Author: kuzinandrey@yandex.ru
#  URL: https://www.github.com/KuzinAndrey/kavsprayvpn
#
###############################################

PROJ = kavsprayvpn
CC = gcc
SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))
LIBS =
BUILD =
CFLAGS = -Wall -Werror -pedantic

ifdef DEBUG
  CFLAGS += -ggdb
else
  CFLAGS += -DPRODUCTION=1
  BUILD = -s
endif

%.o: %.c
	$(CC) $(CFLAGS) -c $<

$(PROJ): $(OBJS)
	$(CC) $(BUILD) $(OBJS) $(PROD) -o $@ $(LIBS)

clean:
	rm -f $(PROJ) *.o

all: $(PROJ)
