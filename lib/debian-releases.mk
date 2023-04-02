# This file defines the variables describing all Debian repositories
# that need to be fetched in the "update-packages" process

define get_config =
$(shell jq -r $(1) 'data/config.json')
endef

MAIN_RELEASES = $(call get_config, '.distributions | to_entries[] | select(.value.release) | .key')
SECURITY_RELEASES = $(filter-out sid, $(MAIN_RELEASES))
BACKPORT_RELEASES = $(SECURITY_RELEASES)

# Define the variables for the release on the main mirror
define add_main_release =
$(1)_MIRROR = $$(MIRROR)
$(1)_DIST = $(1)
$(1)_ARCHS = $(call get_config, '.distributions.$(1).architectures[]')
$(1)_RELEASE = $(1)
ifneq (,$(filter jessie stretch buster bullseye,$(1)))
$(1)_SECTIONS = main contrib non-free
else
$(1)_SECTIONS = main contrib non-free non-free-firmware
endif
$(1)_SUBRELEASE =
RELEASES += $(1)
endef
$(foreach release,$(MAIN_RELEASES),$(eval $(call add_main_release,$(release))))

# Define the variables for the releases on security.debian.org
# https://lists.debian.org/debian-security/2019/06/msg00015.html
# $(1)_security_DIST contains special casing for releases starting
# with bullseye releases. After all of jessie, stretch and buster
# are not anymore supported the case can be removed.
define add_security_release =
$(1)_security_MIRROR = $$(SECURITY_MIRROR)
ifneq (,$(filter jessie stretch buster,$(1)))
$(1)_security_DIST = $(1)/updates
else
$(1)_security_DIST = $(1)-security
endif
$(1)_security_ARCHS = $$($(1)_ARCHS)
$(1)_security_RELEASE = $(1)
$(1)_security_SECTIONS = $$($(1)_SECTIONS)
$(1)_security_SUBRELEASE = security
RELEASES += $(1)_security
endef
$(foreach release,$(SECURITY_RELEASES),$(eval $(call add_security_release,$(release))))

# Define the variables for the *-backports releases
define add_backport_release =
$(1)_backports_MIRROR = $$(MIRROR)
$(1)_backports_DIST = $(1)-backports
$(1)_backports_ARCHS = $$($(1)_ARCHS)
$(1)_backports_RELEASE = $(1)-backports
$(1)_backports_SECTIONS = $$($(1)_SECTIONS)
$(1)_backports_SUBRELEASE =
RELEASES += $(1)_backports
endef
$(foreach release,$(BACKPORT_RELEASES),$(eval $(call add_backport_release,$(release))))
