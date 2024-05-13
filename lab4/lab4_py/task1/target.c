// lab4 target.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


void posoigfu() { puts("Kitty says posoigfu!"); }
void smiaaqur() { puts("Kitty says smiaaqur!"); }
void ogloqnzp() { puts("Kitty says ogloqnzp!"); }
void gqahlnan() { puts("Kitty says gqahlnan!"); }
void egqzasjm() { puts("Kitty says egqzasjm!"); }
void yokmwfln() { puts("Kitty says yokmwfln!"); }
void pbwwinxu() { puts("Kitty says pbwwinxu!"); }
void pccbvosh() { puts("Kitty says pccbvosh!"); }
void dpntmhiv() { puts("Kitty says dpntmhiv!"); }
// void win() { execv("/bin/sh", 0); }
void iqcnbrja() { puts("Kitty says iqcnbrja!"); }
void geoloqwp() { puts("Kitty says geoloqwp!"); }
void dwhtmhip() { puts("Kitty says dwhtmhip!"); }


void raw_gets(char* str)
{
    /*
    Reads a string that ends with ('\n') from STDIN
    Doesn't add ('\0') to the string unlike gets()

    GETS (FF->00)
        buf         \xaa\xbb\xFF\xcc
        stdin       \x22\x22  ||
        gets(buf)             ↓↓
        buf         \x22\x22\x00\xcc

    RAW_GETS (FF->FF)
        buf         \xaa\xbb\xFF\xcc
        stdin       \x22\x22  ||
        raw_gets(buf)         ↓↓
        buf         \x22\x22\xFF\xcc
    */

    char ch = fgetc(stdin);
    int i = 0;
    while (ch != '\n')      // Read byte by byte until '\n'
    {
        str[i] = ch;
        ch = fgetc(stdin);
        ++i;
    }
}


int child_job()
{
    char buf[8] = { 0 };
    puts("Enter something:");
    raw_gets(buf);  // Read raw buffer
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