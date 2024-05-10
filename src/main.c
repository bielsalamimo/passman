#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "passman.h"

static const Option optHelp = {
    .s = "-h",
    .l = "--help",
    .usage = "Print this help message",
    .params = ""
};

static const Option optVersion = {
    .s = "-v" ,
    .l = "--version",
    .usage = "Print version",
    .params = ""
};

static const Option optList = {
    .s = "-l",
    .l = "--list",
    .usage = "List passwords",
    .params = ""
};

static const Option optNew = {
    .s = "-n",
    .l = "--new",
    .usage = "Create a new password",
    .params = "[NAME]"
};

static const Option optDelete = {
    .s = "-d",
    .l = "--delete",
    .usage = "Delete a password",
    .params = "[NAME]"
};

static const Option optPrint = {
    .s = "-p",
    .l = "--print",
    .usage = "Print a password",
    .params = "[NAME]"
};

static const Option optCopy = {
    .s = "-c",
    .l = "--copy",
    .usage = "Copy a password to clipboard",
    .params = "[NAME]"
};

static const Option optRename = {
    .s = "-r",
    .l = "--rename",
    .usage = "Rename a password",
    .params = "[NAME] [NEW NAME]"
};

static const Option optBackup = {
    .s = "-b",
    .l = "--backup",
    .usage = "Backup passwords",
    .params = "[OUTPUT]"
};

int main(int argc, char **argv)
{
    Program passman = {
        .name = "passman",
        .version = "0.4.0",
        .usage = "[option] [arguments...]",
        .options_size = 9
    };

    passman.options = malloc(sizeof(Option) * passman.options_size);
    
    passman.options[0] = optHelp;
    passman.options[1] = optVersion;
    passman.options[2] = optList;
    passman.options[3] = optNew;
    passman.options[4] = optDelete;
    passman.options[5] = optPrint;
    passman.options[6] = optRename;
    passman.options[7] = optBackup;
    passman.options[8] = optCopy;

	char *path_to_passwords = get_path_to_passwords();
	mkdir(path_to_passwords, 0777);

	if (argc == 1 || Option_is(&optHelp, argv)) {
		print_help(&passman);
	} else if (Option_is(&optVersion, argv)) {
		print_version(&passman);
	} else if (Option_is(&optList, argv)) {
		list_passwords();
	} else if (Option_is(&optNew, argv)) {
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
	} else if (Option_is(&optDelete, argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			delete_password(argv[2]);
		}
	} else if (Option_is(&optPrint, argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			print_password(argv[2]);
		}
	} else if (Option_is(&optRename, argv)) {
		if (argc > 4) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 4) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			rename_password(argv[2], argv[3]);
		}
	} else if (Option_is(&optBackup, argv)) {
		if (argc > 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "too many arguments\n");
		} else if (argc < 3) {
			fprintf(stderr, COLOR_RED "Error: " COLOR_RESET
						  "not enough arguments\n");
		} else {
			backup_passwords(argv[2], &passman);
		}
	} else if (Option_is(&optCopy, argv)) {
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
		print_help(&passman);
	}

	return 0;
}
