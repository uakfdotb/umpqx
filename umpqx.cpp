#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <cctype>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <stack>
#include <direct.h>
#else
#include <dirent.h>
#endif

#define __STORMLIB_SELF__
#include <StormLib.h>

using namespace std;
typedef struct stat Stat;

map<string, bool> loadedFiles;
vector<string> filesToLoad;

// CONFIGURATION (done through command line)
bool DEBUG = false;
string workingDirectory = "working/";
bool antivirus; //whether to do "antivirus" checks on MPQ while extracting
string mpqHeaderCopy = ""; //filename MPQ to copy header data from when creating MPQ
bool compactMPQ = false; //whether to compact when creating MPQ
bool compress = false; //whether to compress when creating MPQ
bool insertW3MMD = false; //whether to insert W3MMD code into JASS file
bool noWrite = false; //whether to suppress all file output while extracting
bool searchFiles = false; //whether to automatically search for files outside of list files while extracting

//string replace all
void replaceAll(std::string& str, const std::string& from, const std::string& to) {
	size_t start_pos = 0;
	
	while((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
}

// trim from start
static inline std::string &ltrim(std::string &s) {
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
	return s;
}

// trim from end
static inline std::string &rtrim(std::string &s) {
	s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	return s;
}

// trim from both ends
static inline std::string &trim(std::string &s) {
        return ltrim(rtrim(s));
}

bool invalidChar (char c) {  
	return !(c >= 32 && c <= 126);
}

//removes bad characters from filename
void stripUnicode(string & str) {
	str.erase(remove_if(str.begin(),str.end(), invalidChar), str.end());
}

#if defined(_WIN32) || defined(_WIN64)
void rdirfiles(string path, vector<string>& files) {
	if(!path.empty() && path[path.length() - 1] == '/') {
		path = path.substr(0, path.length() - 1);
	}
	
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA ffd;
    string spec;
    stack<string> directories;

    directories.push(path);
    files.clear();

    while (!directories.empty()) {
        path = directories.top();
        spec = path + "\\*";
        directories.pop();

        hFind = FindFirstFile(spec.c_str(), &ffd);
        if (hFind == INVALID_HANDLE_VALUE)  {
            return;
        } 

        do {
            if (strcmp(ffd.cFileName, ".") != 0 && 
                strcmp(ffd.cFileName, "..") != 0) {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    directories.push(path + "\\" );
                    files.push_back(string(ffd.cFileName) + "/");
                }
                else {
                    files.push_back(string(ffd.cFileName));
                }
            }
        } while (FindNextFile(hFind, &ffd) != 0);

        if (GetLastError() != ERROR_NO_MORE_FILES) {
            FindClose(hFind);
            return;
        }

        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
    }
}
#else
//recursively retrieves files from directory
//dir is the directory that we started searching, while prefix is the parent directories in recursion
void rdirfiles (string dir, vector<string> &files, string prefix = "")
{
	//add slash if needed
	if(!dir.empty() && dir[dir.length() - 1] != '/') {
		dir += "/";
	}

    DIR *dp;
    struct dirent *dirp;
    if((dp  = opendir((dir + prefix).c_str())) == NULL) {
        return;
    }

    while ((dirp = readdir(dp)) != NULL) {
    	if(strcmp(dirp->d_name, ".") != 0 && strcmp(dirp->d_name, "..") != 0) {
    		Stat st;
			stat((dir + prefix + string(dirp->d_name)).c_str(), &st);
			if(st.st_mode & S_IFDIR) {
				files.push_back(prefix + string(dirp->d_name) + "/");
				rdirfiles(dir, files, prefix + string(dirp->d_name) + "/");
			} else if(st.st_mode & S_IFREG) {
				files.push_back(prefix + string(dirp->d_name));
			}
        }
    }
    closedir(dp);
}
#endif

void do_mkdir(const char *path) {
#if defined(_WIN32) || defined(_WIN64)
	if ((GetFileAttributes(path)) == INVALID_FILE_ATTRIBUTES) {
		_mkdir(path);
	}
#else 
    Stat st;
    int status = 0;

    if(stat(path, &st) != 0)
    {
		mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }
#endif
}

/**
** mkpath - ensure all directories in path exist
** Algorithm takes the pessimistic view and works top-down to ensure
** each directory in path exists, rather than optimistically creating
** the last element and working backwards.
*/
void mkpath(const char *path) {
    char           *pp;
    char           *sp;
    char           *copypath = strdup(path);

    pp = copypath;
    while ((sp = strchr(pp, '/')) != 0)
    {
        if (sp != pp)
        {
            /* Neither root nor double slash in path */
            *sp = '\0';
            do_mkdir(copypath);
            *sp = '/';
        }
        pp = sp + 1;
    }
    
    delete [] copypath;
}

void getStringStream(char *array, int n, stringstream &ss, bool removeInvalid = false) {
	string str(array, n);
	
	//change all \r to \n, but don't add \r\r
	replaceAll(str, "\r\n", "\r");
	replace(str.begin(), str.end(), '\r', '\n');
	
	if(removeInvalid) {
		//change invalid unicode characters to \n for parsing
		for(int i = 0; i < 32; i++) {
			replace(str.begin(), str.end(), (char) i, '\n');
		}
		
		replace(str.begin(), str.end(), (char) 127, '\n');
	}
	
	//set the string for stringstream
	ss.str(str);
}

istream &gettrimline(istream &is, string &str) {
	istream &ret = getline(is, str);
	stripUnicode(str);
	return ret;
}

void addLoadFile(string fileName) {
	stripUnicode(fileName);
	fileName = trim(fileName);
	
	string lowerName = fileName;
	transform(lowerName.begin( ), lowerName.end( ), lowerName.begin( ), (int(*)(int))tolower);

	//make sure we don't already have this file
	if(loadedFiles.find(lowerName) == loadedFiles.end()) {
		filesToLoad.push_back(fileName);
		loadedFiles[lowerName] = true;
		if(DEBUG) cout << "Adding file [" << fileName << "]" << endl;
	}
}

//adds file but also autodetects other files based on it
void addLoadFileAuto(string fileName) {
	if(fileName.length() > 300 || fileName.find('\"') != string::npos || fileName.find(';') != string::npos || fileName.find('\'') != string::npos || fileName.find('[') != string::npos || fileName.find(']') != string::npos) {
		return;
	}
	
	//replace two backslashes with one backslash
	replaceAll(fileName, "\\\\", "\\");
	replaceAll(fileName, "/", "\\");

	addLoadFile(fileName);
	
	//remove index
	string fileNameWithoutExtension = fileName;
	size_t index = fileName.rfind('.');
	
	if(index != string::npos) {
		fileNameWithoutExtension = fileName.substr(0, index);
	}
	
	addLoadFile(fileNameWithoutExtension + ".blp");
	addLoadFile(fileNameWithoutExtension + ".tga");
	addLoadFile(fileNameWithoutExtension + ".mdx");
	addLoadFile(fileNameWithoutExtension + ".mdl");
	addLoadFile(fileNameWithoutExtension + ".mp3");
	addLoadFile(fileNameWithoutExtension + ".wav");
	
	index = fileNameWithoutExtension.rfind('\\');
	string baseName = fileNameWithoutExtension;
	
	if(index != string::npos && fileName.length() >= index) {
		baseName = fileNameWithoutExtension.substr(index + 1);
	}
	
	addLoadFile("ReplaceableTextures\\CommandButtonsDisabled\\DIS" + baseName + ".blp");
	addLoadFile("ReplaceableTextures\\CommandButtonsDisabled\\DIS" + baseName + ".tga");
	addLoadFile("ReplaceableTextures\\CommandButtonsDisabled\\DISBTN" + baseName + ".blp");
	addLoadFile("ReplaceableTextures\\CommandButtonsDisabled\\DISBTN" + baseName + ".tga");
}

void addDefaultLoadFiles() {
	addLoadFile("war3map.j");
	addLoadFile("Scripts\\war3map.j");
	addLoadFile("war3map.w3e");
	addLoadFile("war3map.wpm");
	addLoadFile("war3map.doo");
	addLoadFile("war3map.w3u");
	addLoadFile("war3map.w3b");
	addLoadFile("war3map.w3d");
	addLoadFile("war3map.w3a");
	addLoadFile("war3map.w3q");
	addLoadFile("war3map.w3u");
	addLoadFile("war3map.w3t");
	addLoadFile("war3map.w3d");
	addLoadFile("war3map.w3h");
	addLoadFile("(listfile)");
}

void processList(string fileName, char *array, int n) {
	size_t index = fileName.rfind('.');
	string extension = "";
	
	if(index != string::npos) {
		extension = fileName.substr(index + 1);
	}

	if(fileName == "(listfile)") {
		stringstream ss;
		getStringStream(array, n, ss);
		string str;
		
		while(getline(ss, str)) {
			addLoadFile(str);
		}
	} else if(extension == "txt" || extension == "slk") {
		stringstream ss;
		getStringStream(array, n, ss);
		string str;
		
		while(getline(ss, str)) {
			if(str.length() < 300) {
				addLoadFileAuto(str);
			
				size_t firstQuote = str.rfind('\"');
			
				if(firstQuote != string::npos) {
					string sub = str.substr(0, firstQuote);
					size_t secondQuote = sub.rfind('\"');
				
					if(secondQuote != string::npos && secondQuote < sub.length()) {
						addLoadFileAuto(sub.substr(secondQuote + 1));
					}
				}
			
				size_t equalIndex = str.rfind('=');
			
				if(equalIndex != string::npos && equalIndex < str.length()) {
					addLoadFileAuto(str.substr(equalIndex + 1));
				}
			}
		}
	} else if(extension == "w3u" || extension == "w3t" || extension == "w3b" || extension == "w3d" || extension == "w3a" || extension == "w3h" || extension == "w3q" || extension == "mdx" || extension == "w3i") {
		stringstream ss;
		getStringStream(array, n, ss, true);
		string str;
		
		while(getline(ss, str)) {
			addLoadFileAuto(str);
		}
	} else if(extension == "j") {
		stringstream ss;
		getStringStream(array, n, ss);
		string str;
		
		while(getline(ss, str)) {
			size_t firstQuote;
			
			while((firstQuote = str.rfind('\"')) != string::npos) {
				str = str.substr(0, firstQuote);
				size_t secondQuote = str.rfind('\"');
			
				if(secondQuote != string::npos && secondQuote < str.length()) {
					addLoadFileAuto(str.substr(secondQuote + 1));
					str = str.substr(0, secondQuote);
				} else {
					break;
				}
			}
		}
	}
}

bool loadListFile(string fileName) {
	cout << "Loading list file [" << fileName << "]" << endl;

	ifstream fin(fileName.c_str());
	
	if(!fin.is_open()) {
		cerr << "Warning: failed to open list file; only default files will be loaded" << endl;
		return false;
	}
	
	string str;
	
	while(getline(fin, str)) {
		addLoadFile(str);
	}

	return true;
}

void writeW3MMD(ofstream &fout, char *array, int n) {
	//ss is constructed from array, which contains the JASS script
	stringstream ss;
	getStringStream(array, n, ss);

	//open up input stream from w3mmd.txt that tells us how to insert W3MMD code
	ifstream fin("w3mmd.txt");
	
	if(!fin.is_open()) {
		cerr << "Warning: failed to open w3mmd.txt for W3MMD insertion" << endl;
		return;
	}
	
	string str;
	bool startOutput; //whether first line detect from w3mmd.txt was reached
	
	//loop on the W3MMD file
	while(gettrimline(fin, str)) {
		//ignore comments
		if(!str.empty() && str[0] == '#') {
			continue;
		}
		
		//colons indicate to wait until a certain line is arrived at
		if(str[0] == ':') {
			string lineDetect = str.substr(1);
			
			//don't need str anymore so reuse
			//read from JASS script until we reach the line
			while(gettrimline(ss, str) && str != lineDetect) {
				fout << str << endl;
			}
			
			//if we have EOF, print warning
			//otherwise write the last line
			if(ss.eof()) {
				cerr << "Warning: EOF reached before [" << lineDetect << "] line was reached" << endl;
			} else {
				fout << str << endl;
			}
			
			//now continue reading W3MMD from loop
			startOutput = true;
		} else if(startOutput) {
			fout << str << endl;
		}
	}
	
	//write the remainder of JASS script out
	while(gettrimline(ss, str)) {
		fout << str << endl;
	}
}

void saveFile(string fileName, char *array, int n) {
	if(searchFiles) {
		//process the file to search for more files
		processList(fileName, array, n);
	}

	replace(fileName.begin(), fileName.end(), '\\', '/');
	fileName = workingDirectory + fileName;
	
	//make directories if needed
	string directoryName = fileName;
	size_t index = fileName.rfind('/');
	
	if(index != string::npos) {
		directoryName = fileName.substr(0, index + 1);
	}
	
	mkpath(directoryName.c_str());
	
	//run antivirus check here on JASS
	//if we do in processList it won't be done if search is disabled
	//if we do in insertW3MMD then write may be disabled and it won't work
	if(antivirus && fileName.length() >= 9 && fileName.substr(fileName.length() - 9) == "war3map.j") {
		stringstream ss;
		getStringStream(array, n, ss);
		string str;
		
		while(getline(ss, str)) {
			//check for preload exploit in map
			if(str.find("PreloadGenEnd") != string::npos) {
				cout << "Virus detected in map: " << str << endl;
			}
		}
	}
	
	//save the file, but only if noWrite is not enabled
	if(!noWrite) {
		ofstream fout(fileName.c_str());
	
		//if JASS, insert W3MMD if requested
		if(insertW3MMD && fileName.length() >= 9 && fileName.substr(fileName.length() - 9) == "war3map.j") {
			writeW3MMD(fout, array, n);
		} else {
			if(fout.is_open()) {
				fout.write(array, n);
				fout.close();
			} else {
				cerr << "Warning: failed to save file [" << fileName << "]" << endl;
			}
		}
	}
}

bool loadMPQ(string fileName) {
	HANDLE MapMPQ;

	if(SFileOpenArchive(fileName.c_str( ), 0, MPQ_OPEN_FORCE_MPQ_V1 | STREAM_FLAG_READ_ONLY, &MapMPQ)) {
		cout << "Loading MPQ [" << fileName << "]" << endl;
	} else {
		cerr << "Error: unable to load MPQ file [" << fileName << "]: " << GetLastError() << endl;
		return false;
	}
	
	for(unsigned int i = 0; i < filesToLoad.size(); i++) {
		string currentFile = filesToLoad[i];
		if(DEBUG) cout << "Loading file [" << currentFile << "]" << endl;
		HANDLE SubFile;

		if(SFileOpenFileEx(MapMPQ, currentFile.c_str( ), 0, &SubFile)) {
			if(DEBUG) cout << "Found file [" << currentFile << "]" << endl;
			unsigned int FileLength = SFileGetFileSize(SubFile, NULL);

			if(FileLength > 0 && FileLength != 0xFFFFFFFF) {
				char *SubFileData = new char[FileLength];
				DWORD BytesRead = 0;

				if(SFileReadFile(SubFile, SubFileData, FileLength, &BytesRead, NULL)) {
					//since it succeeded, FileLength should equal BytesRead
					saveFile(currentFile, SubFileData, BytesRead);
				}

				delete [] SubFileData;
			}

			SFileCloseFile(SubFile);
		}
	}
	
	SFileCloseArchive(MapMPQ);
	
	return true;
}

bool makeMPQ(string fileName) {
	vector<string> files;
	rdirfiles(workingDirectory, files);
	
	HANDLE MapMPQ;

	if(SFileCreateArchive(fileName.c_str( ), MPQ_CREATE_ARCHIVE_V1, files.size() + 15, &MapMPQ)) {
		cout << "Creating MPQ [" << fileName << "]" << endl;
	} else {
		cerr << "Error: unable to create MPQ file [" << fileName << "]: " << GetLastError() << endl;
		return false;
	}
	
	//parameters for adding file to archive
	int dwFlags = 0;
	int dwCompression = 0;
	int dwCompressionNext = 0;
	
	if(compress) {
		dwFlags = MPQ_FILE_COMPRESS;
		dwCompression = MPQ_COMPRESSION_ZLIB;
		dwCompressionNext = MPQ_COMPRESSION_ZLIB;
	}
	
	for(unsigned int i = 0; i < files.size(); i++) {
		string currentFile = files[i];
		
		if(currentFile.empty()) continue;
		
		if(currentFile[currentFile.length() - 1] == '/') {
			if(DEBUG) cout << "Ignoring directory [" << currentFile << "]" << endl;
		} else if(currentFile == "(listfile)") {
			cout << "Ignoring listfile [" << currentFile << "]" << endl;
		} else {
			if(DEBUG) cout << "Adding file [" << currentFile << "]" << endl;
			
			//change to backslash that MPQ uses for the filename in MPQ
			string mpqFile = currentFile;
			replace(mpqFile.begin(), mpqFile.end(), '/', '\\');
			
			if(!SFileAddFileEx(MapMPQ, (workingDirectory + currentFile).c_str( ), mpqFile.c_str(), dwFlags, dwCompression, dwCompressionNext)) {
				cerr << "Warning: failed to add " << currentFile << endl;
			}
		}
	}
	
	if(compactMPQ) {
		if(!SFileCompactArchive(MapMPQ, NULL, 0)) {
			cerr << "Warning: failed to compact archive: " << GetLastError() << endl;
		}
	}
	
	SFileCloseArchive(MapMPQ);
	
	if(!mpqHeaderCopy.empty()) {
		cout << "Prepending header from [" << mpqHeaderCopy << "] to [" << fileName << "]" << endl;
		
		//copy header to the mpq, use temporary file with _ prepended
		string tempFileName = "_" + fileName;
		
		//read header first
		ifstream fin(mpqHeaderCopy.c_str());
		
		if(!fin.is_open()) {
			cerr << "Error: failed to copy header data: error while reading [" << mpqHeaderCopy << "]" << endl;
			return false;
		}
		
		char *buffer = new char[512];
		fin.read(buffer, 512);
		
		if(fin.fail()) {
			cerr << "Warning: header data could not be completely read" << endl;
		}
		
		fin.close();
		
		ofstream fout(tempFileName.c_str());
	
		if(!fout.is_open()) {
			cerr << "Error: failed to copy header data: error while writing to [" << tempFileName << "]" << endl;
			delete [] buffer;
			return false;
		}
		
		fout.write(buffer, 512);
		
		//now add the actual MPQ data, use same buffer
		ifstream finMPQ(fileName.c_str());
		
		if(!finMPQ.is_open()) {
			cerr << "Error: failed to prepend header to MPQ: error while reading MPQ [" << fileName << "]" << endl;
			delete [] buffer;
			return false;
		}
		
		while(!finMPQ.eof()) {
			finMPQ.read(buffer, 512);
			fout.write(buffer, finMPQ.gcount()); //use gcount in case less than 512 bytes were read
		}
		
		delete [] buffer;
		fout.close();
		finMPQ.close();
		
		if(rename(tempFileName.c_str(), fileName.c_str()) != 0) {
			cerr << "Error while renaming [" << tempFileName << "] to [" << fileName << "]" << endl;
			return false;
		}
	}
	
	return true;
}

int main(int argc, const char **argv) {
	addDefaultLoadFiles();

	bool createMPQ = false; //whether to create MPQ instead of extract one
	int argi = 1;
	
	//get options first
	for(; argi < argc - 1 && argv[argi][0] == '-'; argi++) {
		if(strcmp(argv[argi], "-c") == 0 || strcmp(argv[argi], "-create") == 0) {
			createMPQ = true;
		} else if(strcmp(argv[argi], "-w") == 0 || strcmp(argv[argi], "-working") == 0) {
			argi++;
			
			if(argi < argc - 1) {
				workingDirectory = argv[argi];
				
				if(!workingDirectory.empty() && workingDirectory[workingDirectory.length() - 1] != '/') {
					workingDirectory = workingDirectory + "/";
				}
			}
		} else if(strcmp(argv[argi], "-d") == 0 || strcmp(argv[argi], "-debug") == 0) {
			DEBUG = true;
		} else if(strcmp(argv[argi], "-av") == 0 || strcmp(argv[argi], "-antivirus") == 0) {
			antivirus = true;
		} else if(strcmp(argv[argi], "-header") == 0 || strcmp(argv[argi], "-copy") == 0) {
			argi++;
			
			if(argi < argc - 1) {
				mpqHeaderCopy = argv[argi];
			}
		} else if(strcmp(argv[argi], "-compact") == 0) {
			compactMPQ = true;
		} else if(strcmp(argv[argi], "-compress") == 0) {
			compress = true;
		} else if(strcmp(argv[argi], "-w3mmd") == 0) {
			insertW3MMD = true;
		} else if(strcmp(argv[argi], "-now") == 0 || strcmp(argv[argi], "-nowrite") == 0) {
			noWrite = true;
		} else if(strcmp(argv[argi], "-s") == 0 || strcmp(argv[argi], "-search") == 0) {
			searchFiles = true;
		} else {
			cout << "Skipping unknown option " << argv[argi] << endl;
		}
	}
	
	if(!createMPQ) {
		if(argi < argc - 1) {
			for(; argi < argc - 1; argi++) {
				loadListFile(argv[argi]);
			}
		} else {
			loadListFile("listfile.txt");
		}
	
		string mpqfile = "a.mpq";
	
		if(argi < argc) {
			mpqfile = argv[argi];
		}
	
		loadMPQ(mpqfile);
	} else {
		string mpqfile = "a.mpq";
	
		if(argi < argc) {
			mpqfile = argv[argi];
		}
		
		makeMPQ(mpqfile);
	}
}
