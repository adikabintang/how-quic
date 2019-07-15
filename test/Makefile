LOG_SOURCE=../third_party/log.c/src

.PHONY: quic_test.out
quic_test:
	gcc -o quic_test.out ../src/quic.c quic_test.c \
		-I$(LOG_SOURCE) \
		../obj/log.o \
		-I../include -lcriterion