#define PATH_LIMIT 200

#include <sodium.h>
#define CHUNK_SIZE 4096
#define KEY_LEN crypto_box_SEEDBYTES

int option_is(const char opt[], const char option_long[], char **argv);
char *get_path_to_passwords(void);
int encrypt(const char *target_file, const char *source_file,
	    char *master_password);
int decrypt(const char *target_file, const char *source_file,
	    char *master_password);
void no_extension(const char *s);

// Compare options with command arguments
int option_is(const char opt[], const char option_long[], char **argv)
{
	if (!strcmp(argv[1], opt) || !strcmp(argv[1], option_long)) {
		return 1;
	}
	return 0;
}

// this will return $HOME/.config/passman/
char *get_path_to_passwords(void)
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
		fprintf(stderr, "Error: Out of memory\n");
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
		fprintf(stderr, "Error: out of memory\n");
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
