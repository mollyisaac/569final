  /usr/bin/clang++ -std=c++17 -fsanitize=fuzzer,address ./Fuzz.cpp -I/home/fuzzusers/openafis/lib/ -L/home/fuzzusers/openafis/lib -lopenafis -o fuzz
   ./fuzz -max_len=666666 data/valid/fvc2002/DB1_B/

