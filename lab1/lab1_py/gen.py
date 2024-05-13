import random
import string


def pad():
    for _ in range(random.randrange(0, 10)):
        r = "".join(random.choices(string.ascii_lowercase, k = 8))
        print(f'void {r}() {{ puts("Kitty says {r}!"); }}')


print("""// lab1 target.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
""")

pad()
print('void win() { execv("/bin/sh", 0); }')
pad()

len = random.randrange(5, 25)
print(f"""
int main() {{
    int pwd[{len}] = {{ 0 }};
    char buf[{len}] = {{ 0 }};
    gets(buf);
    if (pwd[0] != 1337)
        exit(1);
    else
        puts("ACCESS GRANTED!");
}}""")
