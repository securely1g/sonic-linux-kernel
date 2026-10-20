# Reuse Debian's maintained kbuild install recipes without its binary package
# targets. This target only populates DESTDIR; it never runs dh_builddeb.
include debian/rules.real

.PHONY: sonic-install-kbuild
sonic-install-kbuild: build_kbuild
	$(call make-tools,certs) install DESTDIR=$(DESTDIR) prefix=/usr/lib/linux-kbuild-$(ABINAME)
	$(call make-tools,scripts) install DESTDIR=$(DESTDIR) prefix=/usr/lib/linux-kbuild-$(ABINAME)
	$(call make-tools,tools/bpf/resolve_btfids) install DESTDIR=$(DESTDIR) prefix=/usr/lib/linux-kbuild-$(ABINAME)
	$(call make-tools,tools/objtool) install DESTDIR=$(DESTDIR) prefix=/usr/lib/linux-kbuild-$(ABINAME)
