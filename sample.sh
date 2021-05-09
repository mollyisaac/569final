/usr/bin/clang++ -std=c++17 -fsanitize=address ./fuzzmain.cpp -I/home/fuzzusers/openafis/lib/ -L/home/fuzzusers/openafis/lib -lopenafis -o fuzzmain

./fuzzmain
