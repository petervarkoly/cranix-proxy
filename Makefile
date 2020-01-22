HERE		= $(shell pwd)
PACKAGE		=oss-proxy
SUBDIRS		=etc usr var srv
REPO		=/data1/OSC/home:varkoly:OSS-4-1:leap15.1

dist:
		echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		echo "Read shalla list if necesary:"
		echo "   wget http://www.shallalist.de/Downloads/shallalist.tar.gz"
		echo "   tar xzf shallalist.tar.gz"
		echo "   mv shallalist.tar.gz var/lib/squidGuard/db/shallalist.tar.gz"
		echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
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

