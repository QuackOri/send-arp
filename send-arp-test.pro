TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
	arp.cpp \
	arphdr.cpp \
	ethhdr.cpp \
	ip.cpp \
	mac.cpp \
	main.cpp

HEADERS += \
	arp.h \
	arphdr.h \
	ethhdr.h \
	ip.h \
	mac.h
