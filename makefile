CC=gcc
LDFLAGS=$(shell pkg-config --libs libnl-genl-3.0)
DEBUG_FLAGS=-DDEBUG=1 -std=c99 -Wall -Wextra -Wpedantic -g 
FLAGS=-std=c99 -Wall -Wpedantic -Wno-unused-parameter
ifeq (${DEBUG},1)
	FLAGS+=${DEBUG_FLAGS}
endif
FLAGS += $(shell pkg-config --cflags libnl-genl-3.0)

nl80211_stats: nl80211_stats.o
	${CC} -o $@ nl80211_stats.o ${LDFLAGS} ${FLAGS}

nl80211_stats.o: nl80211_stats.c
	${CC} -o $@ -c $< ${FLAGS}

clean:
	rm -rf *.o
