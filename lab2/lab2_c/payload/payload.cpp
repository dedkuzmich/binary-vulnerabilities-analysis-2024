#include <windows.h>
#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
    MessageBoxA(0, "Message 1337", "Title 1337", 0);
    cout << "Log 1337" << endl;
    system("pause");
    return EXIT_SUCCESS;
}