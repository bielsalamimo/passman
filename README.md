# passman
Simple password manager in C.

# Dependencies
```
sudo pacman -S libsodium gcc clang libtar xclip
```

# Install
```
git clone https://github.org/bielxvf/passman
cd passman
sudo make clean install
```

# TODO
* [ ] Restore from .tar backup
* [ ] Ask for master password before deleting a password

# Contributing
- Use `clang-format` on all files (`make format` runs it)