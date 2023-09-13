MANPREFIX = /usr/share/man

passman:
	$(CC) src/passman.c -o passman -ltar -lsodium
	clang-format -i src/*

install: passman
	@mkdir -p $(DESTDIR)$(PREFIX)/usr/bin
	/bin/cp -vf passman $(DESTDIR)$(PREFIX)/usr/bin
	chmod 755 $(DESTDIR)$(PREFIX)/usr/bin/passman

clean:
	@rm -f passman
