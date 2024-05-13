// lab4 target.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int child_job()
{   
    // PWD
    // Cannot overwrite pwd array because pwd is located higher than buf in the stack:
    // pwd = dword ptr - 30h
    // buf = byte ptr - 10h
    // var_8 = qword ptr - 8   // Canary

    // GETS
    // Cannot brute-force stack canary byte by byte because gets() adds null terminator to input
    // gets() overwrites the next canary byte with 00. 
    // Assume canary = 0x6ba3440b50f76e00
    // So when I guess 1st byte of canary (which is 00), gets() overwrites 2nd byte withh 00:
    // 6b a3 44 0b 50 f7 00 00
    // 6b a3 44 0b 50 f7 00 01
    // 6b a3 44 0b 50 f7 00 02
    // ...
    // 6b a3 44 0b 50 f7 00 ff

    // CODE
    int pwd[8] = { 0 };     // FAIL
    char buf[8] = { 0 };
    gets(buf);              // FAIL
    if (pwd[0] != 1337)
        exit(1);
    else
        puts("ACCESS GRANTED!");
    return 0;
}


int main(int argc, char* argv[])
{
    // Parent process
    while (1)
    {
        int pid = fork();
        if (pid == 0)
        {
            // Child process
            printf("\n[*] PID = %d\n", getpid());
            child_job();
            puts("[+] Everything is fine");
            exit(0);
        }
        else 
        {
            // Wait for child process to end
            int status;
            wait(&status);
            puts("[*] Child process ended");
        }
    }
    return 0;
}