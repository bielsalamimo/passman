#ifndef _PASSMAN_H
#define _PASSMAN_H

#define COLOR_RED "\x1b[1;31m" // Bold
#define COLOR_RESET "\x1b[0m"

typedef struct {
    char *s;
    char *l;
    char *usage;
    char *params;
} Option;

typedef struct {
    char *name;
    char *version;
    char *usage;
    size_t options_size;
    Option *options;
} Program;

int Option_is(const Option *opt, char **argv);
char *get_path_to_passwords(void);
int encrypt(const char *target_file, const char *source_file, char *master_password);
int decrypt(const char *target_file, const char *source_file, char *master_password);
void no_extension(const char *s);
void Option_print(const Option *opt);
void print_help(const Program *program);
void print_version(const Program *program);
void list_passwords();
void new_password(char *name, char *password);
void print_password(char *name);
void delete_password(char *name);
void rename_password(char *from, char *to);
void backup_passwords(char *path);
void copy_password(char *name, char *progname);

#endif // _PASSMAN_H
