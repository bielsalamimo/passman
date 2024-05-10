#ifndef _OPTION_H
#define _OPTION_H

typedef struct {
	char *s;
	char *l;
	char *usage;
	char *params;
} Option;

int Option_is(const Option *opt, char **argv);
void Option_print(const Option *opt);

void Option_print(const Option *opt)
{
	fprintf(stderr, "\t%s,%s", opt->s, opt->l);
	if (strlen(opt->params) > 0) {
		fprintf(stderr, " %s", opt->params);
	}
	fprintf(stderr, "\t%s\n", opt->usage);
}

int Option_is(const Option *opt, char **argv)
{
	if (!strcmp(argv[1], opt->s) || !strcmp(argv[1], opt->l)) {
		return 1;
	}
	return 0;
}

#endif // _OPTION_H
