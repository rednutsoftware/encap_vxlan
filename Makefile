#
# Makefile for encap_vxlan

# target
LM =		encap_vxlan
LM_SRCS =	encap_vxlan.c
LM_OBJS =	$(LM_SRCS:.c=.o)

############################################################

#
LDLIBS += -lpcap

############################################################

V = 0

ACTUAL_CC := $(CC)
CC_0 =	@echo "Compiling $< ..."; $(ACTUAL_CC)
CC_1 =	$(ACTUAL_CC)
CC =	$(CC_$V)
CC_LINK_0 =	@echo "Linking $@ ..."; $(ACTUAL_CC)
CC_LINK_1 =	$(ACTUAL_CC)
CC_LINK =	$(CC_LINK_$V)

############################################################

# phony target
.PHONY: all

#
all: $(LM)

#
$(LM): $(LM_OBJS)
	$(CC_LINK) $(LDFLAGS) $(filter %.o, $^) $(LDLIBS) -o $@

#
clean:
	-$(RM) $(LM) $(LM_OBJS)

############################################################

# EOF
