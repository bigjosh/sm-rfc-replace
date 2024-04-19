// sm-replychain-tools.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <iomanip>
#include <fstream>

#include <errno.h>

// Function to calculate the hash value of a string using DJB2 algorithm
std::string MakeHash(const std::string& txt) {
    unsigned long hash = 53816;

    for (size_t nC = 0; nC < txt.length(); ++nC) {
        unsigned char ch = std::tolower(txt[nC]);
        hash = ((hash << 5) + hash) + ch; // hash * 33 + ch
        hash = hash % 0xFFFFF; // Limit hash to 20 bits
    }

    std::stringstream ss;
    ss << std::hex << std::setw(5) << std::setfill('0') << hash; // Convert hash to hexadecimal string
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

int quickCheckEmailFileForReplyTo(const char* filePath, const char* magicReplyToAddress) {

    FILE* f;

    errno_t error = fopen_s( &f , filePath, "rt");

    if (error != 0) {

        char errorMsg[256]; // Buffer to hold the error message

        // Use strerror_s to safely get the error message
        strerror_s(errorMsg, sizeof(errorMsg), errno);

        std::cerr << "cannot open file " << filePath << "error:" << errorMsg << std::endl;

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


int quickCheckMatch(const char* filePath , const) {

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


int main( int argc , char ** argv)
{
    if (argc != 4) {
        std::cout << R"(Expects 2 args [special replyto address string (with<>) to replace] and [printf fmt string for new address with %s where the hash goes])" << std::endl;
        return 0; 
    }
    std::cout << "begin" << "\n";

    const char* fileName = argv[1];
    const char* magicReplytoAddress = argv[2];
    const char* replacementAddressFmtStr = argv[3];

    if (quickCheckEmailFileForReplyTo(fileName, magicReplytoAddress)) {
        std::cout << "YES!" << std::endl;
    }
    else {
        std::cout << "No." << std::endl;
    }


    std::cout << "end" << "\n";


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
