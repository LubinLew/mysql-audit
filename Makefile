
DOCKER_IMAGE_NAME := mysql-audit-compiler
DOCKER_IMAGE_TAG  := latest

####################################################################

.PHONY:all
all:
	@ docker run --rm -it -v `pwd`/src:/src -w /src ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG} make all -j`nproc`


.PHONY:clean
clean:
	@ docker run --rm -it -v `pwd`/src:/src -w /src ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG} make clean


.PHONY:env
env:
	@ bash env/build.sh ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}


.PHONY:strip
strip:
	@ objcopy --only-keep-debug src/mysql-audit src/mysql-audit-debug.symbol
	@ strip -s src/mysql-audit
	@ objcopy --add-gnu-debuglink=src/mysql-audit-debug.symbol src/mysql-audit
