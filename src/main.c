#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "passman.h"


int main(int argc, char **argv)
{
	copt_program_init("passman", "0.5.0", "[OPTION] [ARGS...]");

	copt_add_option("help", "-h", "--help", "Print help message", "");
	copt_add_option("version", "-v", "--version", "Print version", "");
	copt_add_option("list", "-l", "--list", "List passwords", "");
	copt_add_option("new", "-n", "--new", "Create a new password",
			"[NAME]");
	copt_add_option("delete", "-d", "--delete", "Delete a password",
			"[NAME]");
	copt_add_option("print", "-p", "--print", "Print a password", "[NAME]");
	copt_add_option("copy", "-c", "--copy", "Copy a password to clipboard",
			"[NAME]");
	copt_add_option("rename", "-r", "--rename", "Rename a password",
			"[NAME] [NEW NAME]");
	copt_add_option("backup", "-b", "--backup",
			"Backup password directory into a .tar", "[OUTPUT]");

	char *path_to_passwords = get_path_to_passwords();
	mkdir(path_to_passwords, 0777);

	if (argc == 1 || copt_option_is("help", argv)) {
		copt_print_help();
	} else if (copt_option_is("version", argv)) {
		print_version();
	} else if (copt_option_is("list", argv)) {
		list_passwords();
	} else if (copt_option_is("new", argv)) {
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
	} else if (copt_option_is("delete", argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			delete_password(argv[2]);
		}
	} else if (copt_option_is("print", argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			print_password(argv[2]);
		}
	} else if (copt_option_is("rename", argv)) {
		if (argc > 4) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 4) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			rename_password(argv[2], argv[3]);
		}
	} else if (copt_option_is("backup", argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			backup_passwords(argv[2]);
		}
	} else if (copt_option_is("copy", argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			copy_password(argv[2]);
		}
	} else {
		fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
					  "unrecognised option\n");
		copt_print_help();
	}

	return 0;
}
