KYBER=../../../external/kyber/ref

CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer # -z noexecstack
CFLAGS += -I $(KYBER)
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = pake.c hic.c  $(KYBER)/kem.c $(KYBER)/indcpa.c $(KYBER)/rej_uniform.c $(KYBER)/polyvec.c $(KYBER)/poly.c $(KYBER)/ntt.c $(KYBER)/cbd.c $(KYBER)/reduce.c $(KYBER)/verify.c 
SOURCESFULL = $(SOURCES) rijndael256/rijndael.c rijndael256/tables.c $(KYBER)/fips202.c $(KYBER)/symmetric-shake.c 
HEADERS = pake.h hic.h $(KYBER)/params.h $(KYBER)/kem.h $(KYBER)/indcpa.h $(KYBER)/polyvec.h $(KYBER)/poly.h $(KYBER)/ntt.h $(KYBER)/cbd.h $(KYBER)/reduce.c $(KYBER)/verify.h $(KYBER)/symmetric.h
HEADERSFULL = $(HEADERS) rijndael256/rijndael.h rijndael256/tables.h $(KYBER)/fips202.h

.PHONY: all speed clean

all: test

test: \
  test/test_pake512 \
  test/test_pake768 \
  test/test_pake1024

test/test_pake512: $(SOURCESFULL) $(HEADERSFULL) test/test_pake.c $(KYBER)/randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCESFULL) $(KYBER)/randombytes.c test/test_pake.c -o test_pake512

test/test_pake768: $(SOURCESFULL) $(HEADERSFULL) test/test_pake.c $(KYBER)/randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCESFULL) $(KYBER)/randombytes.c test/test_pake.c -o test_pake768

test/test_pake1024: $(SOURCESFULL) $(HEADERSFULL) test/test_pake.c $(KYBER)/randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESFULL) $(KYBER)/randombytes.c test/test_pake.c -o test_pake1024

clean:
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -f test/test_pake512
	-$(RM) -f test/test_pake768
	-$(RM) -f test/test_pake1024
