TARGET  := mysql-audit
OUTPUT  := objs

##########################################################
CXX     := g++

##########################################################

INCS    := -Imodules -Iutils
CFLAGS  := -Wall -Werror -Wfatal-errors -O0 -g -MD -Wno-invalid-offsetof
DFLAGS  := -D_STRICT_DATA_CHECK
LFLAGS  := -static -lz -lzstd -ltins -lpcap -lhs -lgnutls -lhogweed -lnettle -lgmp -lgcrypt -lgpg-error

##########################################################

OBJECTS := $(patsubst %.cpp,${OUTPUT}/%.o,$(wildcard *.cpp utils/*.cpp modules/*/*.cpp))

##########################################################

all:${TARGET}

${TARGET}: ${OBJECTS}
	@ echo [LINK] Build $@
	@ ${CXX} $^ -o $@ ${LFLAGS}

.PHONY:clean
clean:
	rm -rf ${OUTPUT} ${TARGET}

###############################################

${OUTPUT}/%.o: %.cpp
	@ mkdir -p $(@D)
	@ echo "[CXX]  $^"
	@ ${CXX} -c ${CFLAGS} ${DFLAGS} ${INCS} $^ -o $@ -std=c++17
