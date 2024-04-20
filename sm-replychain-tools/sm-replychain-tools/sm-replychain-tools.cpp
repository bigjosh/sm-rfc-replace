// sm-replychain-tools.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>

#include <iostream>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <iomanip>
#include <fstream>

#include <errno.h>
#include <regex>
#include <chrono>
#include <string>

// appendLog uses the windows SYCHONIZE attribute to allow safe access from multipule processes
// https://stackoverflow.com/questions/35595983/concurrent-file-write-between-processes#:~:text=clobbering%20each%20other.-,Option%202,-%3A%20Open%20as%20append

// If fileName is empty then returns and does nothing
// message2 is surrounded with single quotes in the logFile

void appendLog(const std::string& fileName, const std::string& message1 , const std::string& message2 , const std::string& message3 ) {

    if (fileName.empty()) return;   // Logging is opptional

    // Get current time
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    // Use localtime_s for safe local time conversion
    std::tm localTime;
    localtime_s(&localTime, &time);

    // Format the date and time
    std::stringstream ss_line;
    ss_line << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S ") << message1 << " '" << message2 << "' " << message3 << "\n";

    auto line = ss_line.str();

    // Convert std::string to a wide string for CreateFile API.
    std::wstring wideFileName(fileName.begin(), fileName.end());

    // Open the file with append and synchronize options.
    HANDLE fileHandle = CreateFile(
        wideFileName.c_str(),                  // File name
        FILE_APPEND_DATA | SYNCHRONIZE,        // Append data and allow synchronize access
        FILE_SHARE_READ | FILE_SHARE_WRITE,    // Share for reading and writing
        NULL,                                  // Default security
        OPEN_ALWAYS,                           // Opens the file, if it exists; otherwise, creates a new file
        FILE_ATTRIBUTE_NORMAL,                 // Normal file attributes
        NULL                                   // No template file
    );

    if (fileHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open the file handle." << std::endl;
        return;
    }

    // Prepare the data to be written
    DWORD bytesWritten;

    // Write to the file
    if (!WriteFile(fileHandle, line.c_str(), static_cast<DWORD>(line.size()), &bytesWritten, NULL)) {
        std::cerr << "Failed to write to the file." << std::endl;
    }
    else {
        std::cout << "Log entry added successfully." << std::endl;
    }

    // Close the handle
    CloseHandle(fileHandle);
}


// Function to calculate the hash value of a string using DJB2 algorithm
std::string MakeHash(const std::string& txt) {
    unsigned long hash = 53816;

    for (size_t nC = 0; nC < txt.length(); ++nC) {
        unsigned char ch = std::tolower(txt[nC]);
        hash = ((hash << 5) + hash) + ch; // hash * 33 + ch
        hash = hash % 0xFFFFF; // Limit hash to 20 bits
    }

    std::stringstream ss;
    ss << std::hex << std::setw(5) << std::setfill('0') <<std::uppercase << hash; // Convert hash to hexadecimal string
    return ss.str();
}


// Function to generate a hashed email address
std::string MakeHashedAddress(const std::string& toaddress) {
    return "josh-" + MakeHash(toaddress) + "@joshreply.com";
}

// Returns 1 if a matching header line is found
// We need this to preserve the optional "name" part of the "mailbox" field.
// This is so ugly, but I think it is the fastest way when majority of lines do not match.
// Reply to address should be ni brakets like <test@test.com>

int checkLineReplyTo(const char* line, const char* magicReplyToAddress) {

    const char* replyToPtr = strstr(line, "Reply-To:");

    if (!replyToPtr) return 0;

    const char* magicAddressPtr = strstr(line, magicReplyToAddress);

    if (!magicAddressPtr) return 0;

    return 1;

}

// Had to break this out becuase c++ has no finally clause. :/

int quickCheckOpenEmailFileForReplyTo(FILE* f, const char* magicReplyToAddress) {

    const int maxLineLne = 1000;    // RFC5322

    char lineBuffer[maxLineLne];

    char* line;

    while ((line = fgets(lineBuffer, maxLineLne, f)) != NULL) {

        if (line[0] == '\x0d') return 0;    // Reached end of headers. Emperically I checked an 0x0d alwasy comes first in SmarterMail EML files. 

        if (checkLineReplyTo(line, magicReplyToAddress)) {
            return 1;
        }
    }

    return 0; 

}

// Quickly check the top of the file to see if we are interested in it. 
// Since we do not care about the vast majority of all email, it is better to do a fast
// check and then start over again with full processing if we do actually care.
// Assumes EML files are text only

// Returns 1 if we care about this file

int quickCheckEmailFileForReplyTo( std::string logFilePathStr, const char* filePath, const char* magicReplyToAddress) {

    FILE* f;

    errno_t error = fopen_s( &f , filePath, "rt");

    if (error != 0) {

        char errorMsg[256]; // Buffer to hold the error message

        // Use strerror_s to safely get the error message
        strerror_s(errorMsg, sizeof(errorMsg), errno);

        appendLog( logFilePathStr, "open file" , filePath, errorMsg);

        return 0;

    }

    const int ret = quickCheckOpenEmailFileForReplyTo(f, magicReplyToAddress);

    fclose(f); 

    return ret;
}

/*

void processEmailFile(const char* filePath, const char* searchString, const char* replaceString) {


    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open file " << filePath << std::endl;
        return; 
    }

    std::string line;
    while (std::getline(file, line)) {
        const char* replyToPtr = strstr(line, "Reply-To:");
        
        
        
        && strstr(line, "Reply-To:") ) {
            file.close();
            return 1; // Return 1 if "this-line" is found
        }
        else if (line.empty()) {
            file.close();
            return 0; // Return 0 if a blank line is encountered
        }
    }

    file.close();
    return 0; // Return 0 if end of file is reached


    // First we read the file into a memory buffer

    FILE* inputFile = fopen(filePath, "rb");
    if (!inputFile) {
        std::cerr << "Error: Unable to open file " << filePath << ": " << strerror(errno) << std::endl;
        return;
    }

    // Get the file size
    fseek(inputFile, 0, SEEK_END);
    long fileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    // Allocate buffer for file content plus a terminating null so we can use strstr. Sorry I hate this too. 
    char* buffer = new char[fileSize+1];
    if (!buffer) {
        std::cerr << "Error: Memory allocation failed." << std::endl;
        fclose(inputFile);
        return;
    }

    // Read file content into buffer
    size_t bytesRead = fread(buffer, 1, fileSize, inputFile);
    if (bytesRead != fileSize) {
        std::cerr << "Error: Failed to read file content." << std::endl;
        delete[] buffer;
        fclose(inputFile);
        return;
    }

    fclose(inputFile);

    buffer[fileSize] = 0x00;        // Add null terminator

    // First find the blank line that comes at the end of the headers

    char* blankLinePtr = strstr( buffer , "\x0d\x0a");

    if (blankLinePtr != NULL) {            // Are there headers? (Should always be true, but test to be safe)

        char* replytoStrPtr = strstr(buffer, "\x0d\x0aReply-To: josh <josh-ac339@joshreply.com>\x0d\x0a");

        // Check if we found the search string and it is above the blank line (therefore it is in the headers)

        if (replytoStrPtr != NULL && replytoStrPtr < blankLinePtr) {

            // Next get the start of the <to> address

            const char* toStr = "To: <";

            char* toStrPtr = strstr(buffer, toStr );

            if (replytoStrPtr != NULL && toStrPtr < blankLinePtr) {

                // Get the end of the <to> address

            }

        }           

    }

    // Next we check if we are interested in this message
    // Does it contain the search string?


    // Find "this-line" in buffer
    char* pos = buffer;
    while ((pos = strstr(pos, "this-line")) != nullptr) {
        // Check if "this-line" is at the beginning of a line
        if ((pos == buffer || pos[-1] == '\n' || pos[-1] == '\r') &&
            (pos[9] == '\0' || pos[9] == '\n' || pos[9] == '\r')) {
            delete[] buffer;
            file.close();
            return 1; // Return 1 if "this-line" is found
        }
        pos += 9; // Move to the next potential match
    }

    // Perform string replacement in memory
    char* pos = buffer;
    while ((pos = strstr(pos, searchString)) != nullptr) {
        memmove(pos + strlen(replaceString), pos + strlen(searchString), strlen(pos + strlen(searchString)) + 1);
        memcpy(pos, replaceString, strlen(replaceString));
        pos += strlen(replaceString);
    }

    // Write modified content back to the file
    FILE* outputFile = fopen(filePath, "wb");
    if (!outputFile) {
        std::cerr << "Error: Unable to open file " << filePath << ": " << strerror(errno) << std::endl;
        delete[] buffer;
        return;
    }

    fwrite(buffer, 1, fileSize, outputFile);
    fclose(outputFile);

    delete[] buffer;
}


// Creates a new processed file. 

int processFile(const char* filePath , const char *newFile , const char * magicReplytoAddress, const char *replacementAddressFmtStr) {

    // Open a file stream to read from a file named "email.txt"
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return 1; // Exit with an error code
    }

    // Regular expression to find 'Reply-To:' in the headers before a blank line
    std::regex emailRegex(R"(Reply-To:\s*[^<]*<([^>]+)>)");
    std::regex emailRegex(R"(Reply-To:\s*[^<]*<([^>]+)>)");

    std::string line;
    bool found = false;

    // Read the file line by line
    while (getline(file, line)) {
        if (line.empty()) {
            break; // Stop reading if a blank line is detected (end of headers)
        }

        // Search for the regex pattern in the current line
        std::smatch matches;
        if (std::regex_search(line, matches, emailRegex)) {
            if (matches.size() > 1) {
                std::cout << "Email Address: " << matches[1].str() << std::endl;
                found = true;
                break; // Stop reading further as we've found what we were looking for
            }
        }
    }

    file.close(); // Close the file

    if (!found) {
        std::cout << "No email address found in the headers." << std::endl;
    }

    return 0;
}

*/


// Function to transform EML file based on specified conditions. Mostly written by ChatGPT!

// Placeholder for a hash function
const char* hash() {
    static std::string hashValue = "12345abcd";  // Example hash value
    return hashValue.c_str();
}


// Function to transform EML file based on specified conditions
void transformEMLFile(const char* filePath, 
    const char* magicReplytoEmailAddress, const char* newEmailAddressFmtString) {
    std::ifstream inFile(filePath);  // Open the original file for reading
    if (!inFile.is_open()) {
        std::cerr << "Error opening input file." << std::endl;
        return;
    }

    // This must be its own line so that the string is not destroyed until the end of the block
    auto tempFilePathStr = std::string(filePath) + ".tmp";

    const char * tempFilePath = tempFilePathStr.c_str();

    std::ofstream outFile(tempFilePath); // Create a new file for writing
    if (!outFile.is_open()) {
        std::cerr << "Error opening output file." << std::endl;
        inFile.close();  // Make sure to close the input file before exiting
        return;
    }

    std::string line;
    std::regex replyToRegex(R"(^Reply-To:\s*.*)" + std::string(magicReplytoEmailAddress));


    // Read line by line from the old file
    while (std::getline(inFile, line)) {

        // We could use an iterator here and it would be slightly more efficient, but we are only working with a single line here so who cares.
        // Also note that we quickly prescreen every file to make sure it does have a matching reply-to before we ever get here,
        // so no chance that this will end up regexing over the whole body. 

        std::smatch matches;
        if (std::regex_search(line, matches, replyToRegex)) {
            // If the line contains the magic email address, replace it
            std::string newEmail = std::string(newEmailAddressFmtString);

            // How can c++ not have a findAndReplce?
            size_t pos = newEmail.find("%s");
            if (pos != std::string::npos) {
                newEmail.replace(pos, 2, MakeHash("bigjosh@gmail.com")); // Replace %s with the return value of the hash
            }
            line = "Reply-To: " + newEmail; // Update the line with the new email

            outFile << line << std::endl; // Write the line to the new file

            break;          // Only do it one time. 

        } else {
            outFile << line << std::endl; // Write the line to the new file
        }
    }

    // Now quickly process the rest of the file without any more checks or regexes

    // Read line by line from the old file
    while (std::getline(inFile, line)) {
        outFile << line << std::endl; // Write the line to the new file
    }

    inFile.close();
    outFile.close();

    // Delete the orginal file
    int deleteErr = remove( filePath );

    if (deleteErr) {
        std::cerr << "Failed to delete file. Error: " << GetLastError() << std::endl;
        return;
    }

    // Delete the orginal file
    int moveErr = rename( tempFilePath , filePath);

    if (deleteErr) {
        std::cerr << "Failed to delete file. Error: " << GetLastError() << std::endl;
        return;
    }

}

/*
auto words_begin =
    std::sregex_iterator(s.begin(), s.end(), number_regex);
auto words_end = std::sregex_iterator();

std::cout << "Found "
          << std::distance(words_begin, words_end)
          << " numbers:\n";

for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
    std::smatch match = *i;
    std::string match_str = match.str();
    std::cout << match_str << '\n';
} 
*/

int main( int argc , char ** argv)
{
    if (argc!=4 && argc != 5) {
        std::cout << "Expects 3 or 4 args:" << std::endl;
        std::cout << " A special replyto address string(with <>) to search for and replace" << std::endl;
        std::cout << " printf fmt string for new address (with <>) with% s where the hash goes" << std::endl;
        std::cout << " path to the EML file to process" << std::endl;
        std::cout << " optional path to a log directory (with trailing backslash) to keep a record of processed addresses (must have create and append access) and errors" << std::endl;
        return 0; 
    }
    std::cout << "begin" << "\n";

    const char* fileName = argv[1];
    const char* magicReplytoAddress = argv[2];
    const char* replacementAddressFmtStr = argv[3];

    // These default to empty
    std::string logDirNameStr;
    std::string logFileNameStr;

    if (argc == 5) {
        logDirNameStr = argv[4];
        logFileNameStr = logDirNameStr + "log.txt";
    }

    if (!quickCheckEmailFileForReplyTo(  logFileNameStr, fileName, magicReplytoAddress)) {
        std::cout << "No" << std::endl;
    } else {

        std::cout << "Yes." << std::endl;

        transformEMLFile(fileName, magicReplytoAddress, replacementAddressFmtStr);

        std::cout << "end" << "\n";

    }

    return 0;

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
