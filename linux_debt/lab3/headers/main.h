#ifndef MAIN
#define MAIN

#include <string>

using namespace std;

void onSigterm(int flags);

int initPidArg(int argc, char** argv);

string getFormatTimestamp();
string getPrefix(int pid);
void logSystemCall(unsigned long long system_code, int pid);
void logCommand(const char* line, int pid);

int ptraceInit(int pid);

#endif