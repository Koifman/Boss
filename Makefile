INSTALL_TARGET = /usr/bin/boss

$(INSTALL_TARGET): boss.py
	cp boss.py $(INSTALL_TARGET)

install: $(INSTALL_TARGET)

uninstall:
	test -e $(INSTALL_TARGET) && rm $(INSTALL_TARGET)
