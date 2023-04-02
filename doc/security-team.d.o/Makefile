# to be executed on dillon.debian.org
MD=/usr/bin/markdown_py
SOURCES=security_tracker glossary index contact dsa_release  organization  tasks  tips triage
HTMLS=$(patsubst %,$(DEST)/%.html,$(SOURCES))
EXTENSIONS=tables def_list toc

export DEST=$(CURDIR)

all: $(HTMLS)

$(DEST)/%.html: %
	(cat header; /usr/bin/markdown_py $< $(addprefix -x ,$(EXTENSIONS)) ) > $@

.PHONY: clean all rebuild publish

clean: $(HTMLS)
	rm $(HTMLS)

rebuild: clean all

ifeq "$(shell hostname) $(shell whoami)" "dillon security"
publish: $(HTMLS)
	mv $(HTMLS) /srv/security-team.debian.org/htdocs
	cp style.css /srv/security-team.debian.org/htdocs
	cp img/* /srv/security-team.debian.org/htdocs/img
	static-update-component security-team.debian.org
else
$(warning you are not in dillon or you are not security user)
endif
