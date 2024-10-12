#include <iostream>
#include <thread>
#include <unistd.h>
#include <sys/stat.h>
#include "INIReader.h"

using namespace std;

void logMessage(const string& message) {
	cout << " [Backup Daemon] " << message << endl;
}

void backupFolder(const string& source, const string& destination) {
	logMessage("Backup start...");

	string copyCommand = "cp -r " + source + " " + destination;
	system(copyCommand.c_str());

	logMessage("Backup finished.");
}

int main(int argc, char* argv[]) {
	string configPath = "/etc/backup_daemon.ini";
	INIReader reader(configPath);

	if (reader.ParseError() < 0) {
		logMessage("Can't read config file " + configPath);
		return 1;
	}

	string sourceFolder = reader.Get("Paths", "SourceFolder", "");
	string destinationFolder = reader.Get("Paths", "DestinationFolder", "");

	int backupSeconds = reader.GetInteger("BackupSchedule", "BackupSeconds", -1);

	if (sourceFolder.empty() || destinationFolder.empty() || backupSeconds == -1) {
		logMessage("Invalid config file " + configPath);
		return 1;
	}

	while (true) {

		thread th1(backupFolder, sourceFolder, destinationFolder);
		thread th2(backupFolder, sourceFolder, destinationFolder);
		th1.join();
		this_thread::sleep_for(chrono::seconds(backupSeconds));
		th2.join();
		this_thread::sleep_for(chrono::seconds(backupSeconds));
	}

	return 0;
}
