#ifndef _PASSMAN_H
#define _PASSMAN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <libtar.h>
#include <fcntl.h>
#include <limits.h>

#include "color.h"
#include "copt.h"

char *get_path_to_passwords();
int encrypt(const char *target_file, const char *source_file,
	    char *master_password);
int decrypt(const char *target_file, const char *source_file,
	    char *master_password);
void no_extension(const char *s);
void print_version();
void list_passwords();
void new_password(const char *name, const char *password);
void print_password(const char *name);
void delete_password(const char *name);
void rename_password(const char *from, const char *to);
void backup_passwords(const char *path);
void copy_password(const char *name);

#include <sodium.h>
#define CHUNK_SIZE 4096
#define KEY_LEN crypto_box_SEEDBYTES

char *get_path_to_passwords()
{
	char *home = getenv("HOME");
	if (home == NULL)
		exit(1);
	char buff[100];
	sprintf(buff, "%s/.config/passman/", home);
	char *path = buff;

	return path;
}

int encrypt(const char *target_file, const char *source_file,
	    char *master_password)
{
	unsigned char salt[crypto_pwhash_SALTBYTES];
	unsigned char key[KEY_LEN];

	randombytes_buf(salt, sizeof salt);

	if (crypto_pwhash(key, sizeof key, master_password,
			  strlen(master_password), salt,
			  crypto_pwhash_OPSLIMIT_INTERACTIVE,
			  crypto_pwhash_MEMLIMIT_INTERACTIVE,
			  crypto_pwhash_ALG_DEFAULT)
	    != 0) {
		fprintf(stderr,
			COLOR_RED "Error: " COLOR_RESET "Out of memory\n");
		exit(1);
	}

	unsigned char buf_in[CHUNK_SIZE];
	unsigned char buf_out[CHUNK_SIZE
			      + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;

	FILE *fp_t, *fp_s;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	unsigned char tag;

	fp_s = fopen(source_file, "rb");
	fp_t = fopen(target_file, "wb");

	crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
	fwrite(header, 1, sizeof header, fp_t);
	fwrite(salt, 1, crypto_pwhash_SALTBYTES, fp_t);

	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
		eof = feof(fp_s);
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		crypto_secretstream_xchacha20poly1305_push(
			&st, buf_out, &out_len, buf_in, rlen, NULL, 0, tag);
		fwrite(buf_out, 1, (size_t)out_len, fp_t);
	} while (!eof);
	fclose(fp_t);
	fclose(fp_s);

	return 0;
}

int decrypt(const char *target_file, const char *source_file,
	    char *master_password)
{
	unsigned char buf_in[CHUNK_SIZE
			     + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char buf_out[CHUNK_SIZE];
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

	crypto_secretstream_xchacha20poly1305_state st;
	FILE *fp_t, *fp_s;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	int ret = -1;
	unsigned char tag;

	fp_s = fopen(source_file, "rb");
	fp_t = fopen(target_file, "wb");

	unsigned char salt[crypto_pwhash_SALTBYTES];
	fread(header, 1, sizeof header, fp_s);
	fread(salt, 1, crypto_pwhash_SALTBYTES, fp_s);

	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	if (crypto_pwhash(key, sizeof key, master_password,
			  strlen(master_password), salt,
			  crypto_pwhash_OPSLIMIT_INTERACTIVE,
			  crypto_pwhash_MEMLIMIT_INTERACTIVE,
			  crypto_pwhash_ALG_DEFAULT)
	    != 0) {
		fprintf(stderr,
			COLOR_RED "Error: " COLOR_RESET "Out of memory\n");
		exit(1);
	}

	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key)
	    != 0) {
		goto ret;
	}

	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
		eof = feof(fp_s);
		if (crypto_secretstream_xchacha20poly1305_pull(
			    &st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0)
		    != 0) {
			goto ret;
		}
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL
		    && !eof) {
			goto ret;
		}
		fwrite(buf_out, 1, (size_t)out_len, fp_t);
	} while (!eof);

	ret = 0;
ret:
	fclose(fp_t);
	fclose(fp_s);

	return ret;
}

void no_extension(const char *s)
{
	char *r = calloc(strlen(s), sizeof(char));

	int l;
	for (l = strlen(s); 0 < l; l--) {
		if (s[l] == '.') {
			break;
		}
	}

	for (int i = 0; i < l; i++) {
		r[i] = s[i];
	}
	printf("%s\n", r);
}

void list_passwords()
{
	DIR *d;
	struct dirent *dir;
	d = opendir(get_path_to_passwords());
	char filenames_buffer[1000][1000];

	int n = 0;
	if (d) {
		while ((dir = readdir(d)) != NULL) {
			if (!strcmp(dir->d_name, ".")) {
				continue;
			}
			if (!strcmp(dir->d_name, "..")) {
				continue;
			}
			sprintf(filenames_buffer[n], "%s\n", dir->d_name);
			n++;
		}

		closedir(d);
	}

	char *s = malloc(sizeof(char) * PATH_MAX);
	for (int i = 0; i < n; i++) {
		for (int j = i + 1; j < n; j++) {
			if (strcmp(filenames_buffer[i], filenames_buffer[j])
			    > 0) {
				strcpy(s, filenames_buffer[i]);
				strcpy(filenames_buffer[i],
				       filenames_buffer[j]);
				strcpy(filenames_buffer[j], s);
			}
		}
	}

	for (int i = 0; i < n; i++) {
		no_extension(filenames_buffer[i]);
	}
	free(s);
}

void new_password(const char *name, const char *password)
{
	unsigned char key[KEY_LEN];
	if (sodium_init() != 0) {
		exit(1);
	}

	char filename[PATH_MAX - 4];
	sprintf(filename, "%s/%s", get_path_to_passwords(), name);

	char filename_enc[PATH_MAX];
	sprintf(filename_enc, "%s.enc", filename);
	FILE *fp = fopen(filename_enc, "r");
	if (fp != NULL) {
		fprintf(stderr,
			COLOR_RED "Error: " COLOR_RESET "file exists\n");
		exit(1);
	}

	FILE *file_text = fopen(filename, "w");
	if (strcmp(password, " ") == 0) {
		password = getpass("Password: ");
	}
	fprintf(file_text, "%s", password);
	fclose(file_text);


	if (encrypt(filename_enc, filename, getpass("Master password: "))
	    != 0) {
		exit(1);
	}
	remove(filename);
	exit(0);
}

void print_password(const char *name)
{
	unsigned char key[KEY_LEN];
	if (sodium_init() != 0) {
		fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
					  "Could not initialize sodium\n");
		exit(1);
	}
	char filename[PATH_MAX - 4];
	sprintf(filename, "%s/%s", get_path_to_passwords(), name);

	char filename_enc[PATH_MAX];
	sprintf(filename_enc, "%s.enc", filename);

	FILE *file_enc = fopen(filename_enc, "r");
	if (file_enc == NULL) {
		fprintf(stderr,
			COLOR_RED "Error: " COLOR_RESET "File not found\n");
		exit(1);
	}

	if (decrypt(filename, filename_enc, getpass("Master password: "))
	    != 0) {
		fprintf(stderr,
			COLOR_RED "Error: " COLOR_RESET
				  "decrypt(): Could not decrypt file\n");
		remove(filename);
		exit(1);
	}
	FILE *file_text = fopen(filename, "r");
	char ch;
	while ((ch = fgetc(file_text)) != EOF)
		printf("%c", ch);
	printf("\n");

	remove(filename);
	exit(0);
}

void copy_password(const char *name)
{
	char cmd[PATH_MAX];
	sprintf(cmd, "%s -p %s | xclip -r -i -selection clipboard",
		program.name, name);
	system(cmd);
	exit(0);
}

void delete_password(const char *name)
{

	char filename[PATH_MAX];
	sprintf(filename, "%s/%s.enc", get_path_to_passwords(), name);
	printf(COLOR_BOLD "Delete '%s'? [y/N] " COLOR_RESET, name);

	char yes_or_no[100];
	fgets(yes_or_no, 100, stdin);

	if (!strcmp(yes_or_no, "y\n") || !strcmp(yes_or_no, "Y\n")
	    || !strcmp(yes_or_no, "yes\n") || !strcmp(yes_or_no, "YES\n")) {
		int del = remove(filename);
		if (del == 0) {
			printf("File deleted successfully\n");
			exit(0);
		} else {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "could not delete file\n");
			exit(1);
		}
	} else {
		printf("Not deleting '%s'\n", name);
		exit(0);
	}
}

void rename_password(const char *from, const char *to)
{
	char filename[PATH_MAX];
	sprintf(filename, "%s/%s.enc", get_path_to_passwords(), from);

	char newfilename[PATH_MAX];
	sprintf(newfilename, "%s/%s.enc", get_path_to_passwords(), to);
	FILE *fp = fopen(newfilename, "r");
	if (fp != NULL) {
		fprintf(stderr,
			COLOR_RED "Error: " COLOR_RESET "file exists\n");
		exit(1);
	}

	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr,
			COLOR_RED "Error: " COLOR_RESET
				  "file '%s' does not exist\n",
			filename);
		exit(1);
	}

	int r = rename(filename, newfilename);
	if (r) {
		fprintf(stderr,
			COLOR_RED "Error: " COLOR_RESET "rename failed\n");
		exit(1);
	}
	printf("'%s' -> '%s'\n", from, to);
}

void backup_passwords(const char *path)
{
	TAR *ptar;

	char *program_name = (char *)program.name;
	tar_open(&ptar, path, NULL, O_WRONLY | O_CREAT, 0644, TAR_GNU);
	tar_append_tree(ptar, get_path_to_passwords(), program_name);
	tar_append_eof(ptar);
	tar_close(ptar);
}

void print_version()
{
	copt_print_version();
	exit(0);
}

#endif // _PASSMAN_H
