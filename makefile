Biclique: Bicliquemain.o Biclique.o AES.o
	gcc -g -o Biclique Bicliquemain.o Biclique.o AES.o

Bicliqueouttest: Bicliquemain.o Bicliqueoutputtest.o AESoutputtest.o
	gcc -o Bicliqueouttest Bicliquemain.o Bicliqueoutputtest.o AESoutputtest.o

Bicliquemain.o: Bicliquemain.c Biclique.h
	gcc -c Bicliquemain.c -lm

Biclique.o: Biclique.c AES.h Biclique.h
	gcc -c Biclique.c -lm

AES.o: AES.c AES.h
	gcc -c AES.c

AESoutputtest.o: AESoutputtest.c AES.h
	gcc -c AESoutputtest.c

Bicliqueoutputtest.o: Bicliqueoutputtest.c Biclique.h
	gcc -c Bicliqueoutputtest.c -lm

test1: Biclique
	./Biclique 1

test5: Biclique
	./Biclique 5

test10: Biclique
	./Biclique 10

test15: Biclique
	./Biclique 15

test20: Biclique
	./Biclique 20

test25: Biclique
	./Biclique 25

out10: Bicliqueouttest
	./Bicliqueouttest 10

clean:
	rm -f B*.o A*.o