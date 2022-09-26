HERE		= $(shell pwd)
PACKAGE		=cranix-proxy
SUBDIRS		=etc usr var srv
REPO		=/data1/OSC/home:pvarkoly:CRANIX

dist:
		./read_cranix_bl.pl
		if [ -e $(PACKAGE) ] ;  then rm -rf $(PACKAGE) ; fi
		mkdir $(PACKAGE)
		rsync -aC $(SUBDIRS) $(PACKAGE)
		tar jcpf $(PACKAGE).tar.bz2 $(PACKAGE)
		xterm -e git log --raw &
		if [ -d $(REPO)/$(PACKAGE) ] ; then \
			cd $(REPO)/$(PACKAGE); osc up; cd $(HERE);\
		        cp $(PACKAGE).tar.bz2 $(REPO)/$(PACKAGE); \
		        cd $(REPO)/$(PACKAGE); \
			osc addremove; \
			osc vc ; \
		        osc ci -m "New Build Version"; \
		fi
