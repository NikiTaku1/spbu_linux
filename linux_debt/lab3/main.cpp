#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string.h>

#include "headers/system_codes.h"
#include "headers/main.h"

using namespace std;

int pid;

void onSigterm(int signum) {
	cout << "SIGINT" << endl;

	ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
	logCommand("ptrace detached", pid);

	exit(signum);
}


int initPidArg(int argc, char** argv) {
	if (argc != 3) {
		cerr << "wrong arguments count" << endl;
		return -1;
	}

	int cmpRes = strcmp("--pid", argv[1]);
	if (cmpRes) {
		cerr << "wrong argument --pid - " << argv[1] << endl;
		return -1;
	}

	int pid = stoi(argv[2]);
	return pid;
}

string getFormatTimestamp() {
	time_t now = time(0);
	tm* time_struct = localtime(&now);

	stringstream line_stream;
	line_stream << put_time(time_struct, "%d.%m.%YT%H:%M:%S");
	return line_stream.str();
}

string getPrefix(int pid) {
	return to_string(pid) + " [" + getFormatTimestamp() + "] ";
}

void logSystemCall(unsigned long long system_code, int pid) {
	cout << getPrefix(pid) << system_names[system_code] << "(system_code=" << system_code << ")" << endl;
}

void logCommand(const char* line, int pid) {
	cout << getPrefix(pid) << line << endl;
}

int ptraceInit(int pid) {
	int err = ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
	if (err) {
		cerr << "ptrace attach error " << err << endl;
		return err;
	}
	logCommand("ptrace is attached", pid);

	err = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
	if (err) {
		cerr << "ptrace set options error " << err << endl;
		return err;
	}
	logCommand("ptrace set options", pid);

	return 0;
}

int main(int argc, char** argv) {

	signal(SIGINT, onSigterm);

	pid = initPidArg(argc, argv);
	if (pid == -1) {
		return -1;
	}

	int err = ptraceInit(pid);
	if (err) {
		return err;
	}

	user_regs_struct regs;

	int status;
	while (1) {

		// Wait process
		waitpid(pid, &status, 0);

		// Receive registers
		err = ptrace(PTRACE_GETREGS, pid, 0, &regs);
		if (err) {
			cerr << "ptrace get registers error " << err << endl;
			return err;
		}

		logSystemCall(regs.orig_rax, pid);

		if (WIFSTOPPED(status) == 0) {
			break;
		}

		// Continue process
		err = ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
		if (err) {
			cerr << "ptrace continue process error " << err << endl;
			return err;
		}
	}

	err = ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
	if (err) {
		cerr << "ptrace detach error " << err << endl;
		return err;
	}
	logCommand("ptrace detached", pid);

	return 0;
}