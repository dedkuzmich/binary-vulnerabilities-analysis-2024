#include <stdio.h>

int main()
{
	char buf[256];

	// Use "volatile" key word to disable compiler optimization of endless loop below. 
	// Without "volatile", "return 0;" will be ignored by compiler => stack canary won't be set.
	volatile int loop = 1;
	while (loop)
	{
		fgets(buf, sizeof(buf), stdin); // Use fgets() instead of gets() to avoid buffer overflow
		printf(buf);
		fflush(stdout);
	}
	return 0;
}