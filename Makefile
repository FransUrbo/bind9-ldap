BASE_LIBS  = $(shell ../../../isc-config.sh --libs isc dns)
FLAGS = $(shell ../../../isc-config.sh --cflags isc dns)
DIRS = -I../../../lib/isc/include -I../../../lib/dns/include -I../../../lib/isc/unix/include -I../../../lib/isc/nothreads/include

ifdef OFFLINE
DEFINES := $(DEFINES) -DOFFLINE
else
LDAP_LIBS := -lldap -llber

ifdef SECUREBIND
DEFINES := $(DEFINES) -DSECUREBIND_SASL
OBJS=sasl.o
endif

ifdef LDAPDB_TLS
DEFINES := $(DEFINES) -DLDAPDB_TLS
endif

ifdef LDAPDB_LDAPURI
DEFINES := $(DEFINES) -DLDAPDB_LDAPURI
endif
endif

all: zone2ldap ldap2zone

%.o: %.c
	gcc $(DIRS) -g $(FLAGS) $(DEFINES) -c $<

zone2ldap: $(OBJS) zone2ldap.o
	gcc $(DIRS) -g -o zone2ldap $(OBJS) zone2ldap.o \
		-L../../../lib/dns/.libs -L../../../lib/isc/.libs \
		$(BASE_LIBS) $(LDAP_LIBS) -lresolv

ldap2zone: $(OBJS) ldap2zone.o
	gcc $(DIRS) -g -o ldap2zone $(OBJS) ldap2zone.o \
		-L../../../lib/dns/.libs -L../../../lib/isc/.libs \
		$(BASE_LIBS) $(LDAP_LIBS) -lresolv

clean:
	rm -f *~ *.o zone2ldap ldap2zone
