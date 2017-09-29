all: backdoor knocker

backdoor: backdoor.cpp
	g++ backdoor.cpp -o backdoor

knocker: knocker.c
	g++ knocker.c -o knocker
