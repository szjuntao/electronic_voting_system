
paillier_test:
	g++ paillier.c mytest_paillier.cpp -o mytest_paillier -lcrypto
	./mytest_paillier

voting_system:
	g++ paillier.c voting_system.cpp -o voting_system -lcrypto

debug_voting_system:
	g++ paillier.c voting_system.cpp -o voting_system -lcrypto -DDEBUG

run:
	openssl genrsa -out private.pem 2048
	openssl rsa -in private.pem -outform PEM -pubout -out public.pem
	./voting_system voters.txt candidates.txt private.pem public.pem

