/*
 * Passman, the man that manages your passwords.
 * Version:  0.3.7
 * Author(s):  Biel Sala , bielsalamimo@gmail.com
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#include <sodium.h>
#include <libtar.h>
#include <fcntl.h>

#include "passman.h" // functions that help main functions like list_passwords()

#define PATH_LIMIT 200

#define PROGRAM_NAME "passman"
#define VERSION "0.3.7"

#define COLOR_RED "\x1b[1;31m" // Bold (for errors)
#define COLOR_RESET "\x1b[0m"

void print_help(void);
void list_passwords(void);
void new_password(char *name, char *password);
void print_password(char *name);
void delete_password(char *name);
void rename_password(char *from, char *to);
void backup_passwords(char *path);

// Commandline options
const char option_help[] = "-h";
const char option_help_long[] = "--help";

const char option_version[] = "-v";
const char option_version_long[] = "--version";

const char option_list[] = "-l";
const char option_list_long[] = "--list";

const char option_new[] = "-n";
const char option_new_long[] = "--new";

const char option_delete[] = "-d";
const char option_delete_long[] = "--delete";

const char option_print[] = "-p";
const char option_print_long[] = "--print";

const char option_copy[] = "-c";
const char option_copy_long[] = "--copy";

const char option_rename[] = "-r";
const char option_rename_long[] = "--rename";

const char option_backup[] = "-b";
const char option_backup_long[] = "--backup";

void print_help(void)
{
	fprintf(stderr, "usage: %s [-h|l|n|d|c|r|b] [arg]\n", PROGRAM_NAME);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t%s,%s\t\t\t\tPrint this help message\n", option_help,
		option_help_long);
	fprintf(stderr, "\t%s,%s\t\t\t\tPrint version\n", option_version,
		option_version_long);
	fprintf(stderr, "\t%s,%s\t\t\t\tList passwords\n", option_list,
		option_list_long);
	fprintf(stderr, "\t%s,%s [NAME]\t\t\t\tCreate a new password\n",
		option_new, option_new_long);
	fprintf(stderr, "\t%s,%s [NAME]\t\t\tDelete a password\n",
		option_delete, option_delete_long);
	fprintf(stderr, "\t%s,%s [NAME]\t\t\tPrint a password\n", option_print,
		option_print_long);
	fprintf(stderr, "\t%s,%s [NAME]\t\t\tCopy password\n", option_copy,
		option_copy_long);
	fprintf(stderr, "\t%s,%s [NAME] [NEW NAME]\t\tRename a password\n",
		option_rename, option_rename_long);
	fprintf(stderr, "\t%s,%s [path/to/file.tar]\t\tBackup passwords\n",
		option_backup, option_backup_long);
	fprintf(stderr,
		"Advice: Use the same master password for every password\n");
	exit(1);
}

void version(void)
{
	printf("version: %s\n", VERSION);
	exit(0);
}

// list contents of $HOME/.config/passman
void list_passwords(void)
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

	char *s = malloc(sizeof(char) * PATH_LIMIT);
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

void new_password(char *name, char *password)
{
	unsigned char key[KEY_LEN];
	if (sodium_init() != 0) {
		exit(1);
	}


	char filename[PATH_LIMIT];
	sprintf(filename, "%s/%s", get_path_to_passwords(), name);

	char filename_enc[PATH_LIMIT];
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
	char *data = password;
	fprintf(file_text, "%s", data);
	fclose(file_text);


	if (encrypt(filename_enc, filename, getpass("Master password: "))
	    != 0) {
		exit(1);
	}
	remove(filename);
	exit(0);
}

void print_password(char *name)
{
	unsigned char key[KEY_LEN];
	if (sodium_init() != 0) {
		fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
					  "Could not initialize sodium\n");
		exit(1);
	}
	char filename[PATH_LIMIT];
	sprintf(filename, "%s/%s", get_path_to_passwords(), name);

	char filename_enc[PATH_LIMIT];
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

void copy_password(char *name, char *progname)
{
	char cmd[PATH_LIMIT];
	sprintf(cmd, "%s -p %s | xclip -r -i -selection clipboard", progname,
		name);
	system(cmd);
	exit(0);
}

void delete_password(char *name)
{

	char filename[PATH_LIMIT];
	sprintf(filename, "%s/%s.enc", get_path_to_passwords(), name);
	printf("\033[1mDelete '%s'? [y/N]\033[0m ", name);

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

void rename_password(char *from, char *to)
{
	char filename[PATH_LIMIT];
	sprintf(filename, "%s/%s.enc", get_path_to_passwords(), from);

	char newfilename[PATH_LIMIT];
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

void backup_passwords(char *path)
{
	TAR *ptar;

	tar_open(&ptar, "passman_backup.tar", NULL, O_WRONLY | O_CREAT, 0644,
		 TAR_GNU);
	tar_append_tree(ptar, "/home/billy02357/.config/passman", "passman");
	tar_append_eof(ptar);
	tar_close(ptar);

	rename("passman_backup.tar", path);
}

int main(int argc, char **argv)
{
	char *path_to_passwords = get_path_to_passwords();
	mkdir(path_to_passwords, 0777); // Should fail if it exists

	if (argc == 1 || option_is(option_help, option_help_long, argv)) {
		print_help();
	} else if (option_is(option_version, option_version_long, argv)) {
		version();
	} else if (option_is(option_list, option_list_long, argv)) {
		list_passwords();
	} else if (option_is(option_new, option_new_long, argv)) {
		if (argc > 4) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else if (argc == 4) {

			new_password(argv[2], argv[3]);
		} else {
			new_password(argv[2], " ");
		}
	} else if (option_is(option_delete, option_delete_long, argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			delete_password(argv[2]);
		}
	} else if (option_is(option_print, option_print_long, argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			print_password(argv[2]);
		}
	} else if (option_is(option_rename, option_rename_long, argv)) {
		if (argc > 4) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 4) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			rename_password(argv[2], argv[3]);
		}
	} else if (option_is(option_backup, option_backup_long, argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			backup_passwords(argv[2]);
		}
	} else if (option_is(option_copy, option_copy_long, argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			copy_password(argv[2], argv[0]);
		}
	} else {
		fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
					  "unrecognised option\n");
		print_help();
	}

	return 0;
}
