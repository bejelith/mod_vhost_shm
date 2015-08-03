APXS=apxs2
VERSION := $(shell cat VERSION)

mod_vhost_ldap_ng.o: mod_vhost_ldap_ng.c
	$(APXS) -DHAVEPHP -Wc,-g -Wc,-Wall -Wc,-Werror -Wc,-DMOD_VHOST_LDAP_VERSION=\\\"mod_vhost_ldap_ng/$(VERSION)\\\" -c -lldap_r mod_vhost_ldap_ng.c

clean:
	rm -f *.o
	rm -f *.lo
	rm -f *.la
	rm -f *.slo
	rm -rf .libs

install:
	$(APXS) -i mod_vhost_ldap_ng.la

Makefile: Makefile.in config.status
	./config.status $@

config.status: configure
	./config.status --recheck
