PYTHON_MODULES = $(wildcard lib/python/*.py)

MIRROR = http://deb.debian.org/debian
SECURITY_MIRROR = http://security.debian.org/debian-security

# Include the definitions of the releases to be fetched
include lib/*-releases.mk

# There's a "RELEASES" variable defining the name of all releases to
# process. Then for each release, there are 5 associated variables:
# <name>_MIRROR: the base URL of the mirror hosting the repository
# <name>_DIST: the sub-directory in $MIRROR/dists so that
#              $MIRROR/dists/$DIST/Release is a valid URL
# <name>_ARCHS: the list of architectures supported in this release
# <name>_RELEASE: the release name for the security tracker
# <name>_SUBRELEASE: the sub-release identifier for the security tracker

all:
	bin/update-db data/security.db

clean:
	-rm -f data/security.db lib/python/test_security.db
	-rm -f stamps/*-*

.PHONY: check check-syntax

test check: check-syntax

SYNTAX_STAMPS = $(patsubst %,stamps/%-syntax,$(shell bin/check-syntax --get))
check-syntax: $(SYNTAX_STAMPS)
stamps/%-syntax: data/%/list bin/check-syntax $(PYTHON_MODULES)
	bin/check-syntax $* data/$*/list
	touch $@

.PHONY: serve
serve:
	@bash bin/test-web-server

.PHONY: update-packages
update-packages: $(foreach release,$(RELEASES),update-$(release))

# This rule is a bit complicated as we need to escape $ for the shell twice,
# once for the eval and once for the usual make processing
define add_update_rule =
.PHONY: update-$(1)
update-$(1):
	set -e; \
	prefix="$$($(1)_RELEASE)_$$($(1)_SUBRELEASE)"; \
	dist="$$($(1)_DIST)"; \
	mirror="$$($(1)_MIRROR)"; \
	sections="$$($(1)_SECTIONS)"; \
	for section in main $$$$sections ; do \
		bin/apt-update-file \
		    $$$$mirror/dists/$$$$dist/$$$$section/source/Sources \
		    data/packages/$$$${prefix}_$$$${section}_Sources ; \
	        for arch in $$($(1)_ARCHS) ; do \
			bin/apt-update-file \
				$$$$mirror/dists/$$$$dist/$$$$section/binary-$$$$arch/Packages \
				data/packages/$$$${prefix}_$$$${section}_$$$${arch}_Packages ; \
		done; \
	done

endef
$(foreach release,$(RELEASES),$(eval $(call add_update_rule,$(release))))

# Define some common aliases
.PHONY: update-main update-security update-backports
update-main: $(foreach release,$(MAIN_RELEASES),update-$(release))
update-security: $(foreach release,$(SECURITY_RELEASES),update-$(release)_security)
update-backports: $(foreach release,$(BACKPORT_RELEASES),update-$(release)_backports)

supported-update-targets:
	@echo -n "main security backports "
	@echo -n "$(RELEASES) "
	@echo -n "packages lists nvd"

# Other custom update rules
update-lists:
	git fetch -q origin && git checkout -f origin/master -- data

# Since October 16, 2015 the XML data feeds are no longer available for
# download in an uncompressed format.
# As per October 16, 2019, the XML data feeds were discontinued and NVD
# only provides JSON feeds. Cf. https://bugs.debian.org/942670
update-nvd:
	mkdir -p data/nvd
	for x in $$(seq 2002 $$(date +%Y)) ; do \
	  name=nvdcve-1.1-$$x.json.gz; \
	  wget -q -Odata/nvd/$$name https://nvd.nist.gov/feeds/json/cve/1.1/$$name || true; \
	  gzip -f -d data/nvd/$$name || true; \
	done
	bin/update-nvd data/nvd/nvdcve-*.json

# Experimental code to compare the Debian and NVD CVE databases using
# CPE values as common key.
update-compare-nvd:
	mkdir -p data/nvd2
	for x in $$(seq 2002 $$(date +%Y)) ; do \
	  name=nvdcve-2.0-$$x.xml.gz; \
	  wget -q -Odata/nvd2/$$name https://static.nvd.nist.gov/feeds/xml/cve/$$name || true ; \
	  gzip -f -d data/nvd2/$$name || true; \
	done
	bin/compare-nvd-cve 2> compare-nvd-cve.log

update-all: update-nvd update-lists update-packages all
