CXX=g++
CPPFLAGS=-W -O2 -I/root/boost
LDFLAGS=-L/root/boost/stage/lib
LDLIBS=-lboost_thread -lboost_chrono -lpcap -lpthread

all : adv_send_arp

adv_send_arp: main.o
	$(CXX) $(CPPFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

main.o: main.cpp
	$(CXX) $(CPPFLAGS) -c -o $@ $^

clean:
	rm -f *.o adv_send_arp

