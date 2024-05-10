MANPREFIX = /usr/share/man

passman:
	@mkdir -p ./build/
	$(CC) -o ./build/passman ./src/main.c ./src/passman.c -ltar -lsodium

format:
	clang-format -i ./src/*

install: passman
	@mkdir -p $(DESTDIR)$(PREFIX)/usr/bin
	/bin/cp -vf ./build/passman $(DESTDIR)$(PREFIX)/usr/bin
	chmod 755 $(DESTDIR)$(PREFIX)/usr/bin/passman

clean:
	@rm -f ./build/passman
