#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

int main(int argc, char* argv[])
{
	char buf[2048] = {'\0'};
	snprintf(buf, sizeof(buf), "background: pid = %d, stdin = %p, stdout = %p; argc = %d; ", (int)getpid(), stdin, stdout, argc);
	int i = 0;
	for(i = 0; i < argc; i++)
	{
		char buf1[32] = {'\0'};
		snprintf(buf1, sizeof(buf1), "%sargv[%d] = %s", (i > 0)?(", "):(""), i, argv[i]);
		strncat(buf, buf1, sizeof(buf));
	}
	strncat(buf, "\n", sizeof(buf));
	fprintf(stdout, "%s", buf);
	fflush(stdout);

	fprintf(stdout, "onetime: press any character/string, but \"exit\" for exit\n");
	fflush(stdout);

	char opt[32] = {'\0'};
	int kept = 1;
	do
	{
		char* ret = fgets(opt, sizeof(opt), stdin);
		if(ret != NULL)
		{
			fprintf(stdout, "interactive: ret = %p, opt = %p %s", ret, opt, opt);
			fflush(stdout);
		}
		char* e = strstr(opt, "exit");
		if(e != NULL)
		{
			fprintf(stdout, "exit\n");
			fflush(stdout);
			kept = 0;
		}
	} while(kept != 0);
	return EXIT_SUCCESS;
}
