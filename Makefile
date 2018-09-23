CXX := g++
CFLAGS := -g -Wall
AR := ar
OBJS_LIB := liblog.o
TGT_LIB_A := liblog.a
SHARED	:= -shared -fPIC
LDFLAGS	+= -lpthread
TARGET := $(TGT_LIB_A)

all: $(TARGET)

%.o:%.cpp
	$(CXX) -c $(CFLAGS) $< -o $@

$(TGT_LIB_A): $(OBJS_LIB)
	$(AR) rcs $@ $^

clean:
	@rm -f $(OBJS_LIB)
	@rm -f $(TARGET)
	@rm -f $(TGT_LIB_A)*

