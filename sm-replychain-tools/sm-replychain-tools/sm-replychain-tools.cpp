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

#include <vector>

#include <algorithm>
#include <random>
#
std::string generateRandomNineDigitNumberWithLeadingZeros() {
    // Random number generator using the Mersenne Twister engine
    std::random_device rd;  // Obtain a random number from hardware
    std::mt19937 eng(rd()); // Seed the generator
    std::uniform_int_distribution<> distr(0, 999999999); // Define the range

    // Generate a random number in the specified range
    int randomNumber = distr(eng);

    // Convert number to string with leading zeros
    std::stringstream ss;
    ss << std::setw(9) << std::setfill('0') << randomNumber;
    return ss.str();
}


/*

int main() {
    // Example usage with various email header lines
    std::vector<std::string> headers = {
        "From: John Doe <john.doe@example.com>",
        "To: jane.doe@example.com",
        "Cc: Someone Else <someone.else@example.com>, another.one@example.com"
    };

    for (const std::string& header : headers) {
        std::vector<std::string> emails = extractEmails(header);
        std::cout << "Emails found in: \"" << header << "\"\n";
        for (const std::string& email : emails) {
            std::cout << "  - " << email << std::endl;
        }
    }

    return 0;
}

*/



// appendLog uses the windows SYCHONIZE attribute to allow safe access from multipule processes
// https://stackoverflow.com/questions/35595983/concurrent-file-write-between-processes#:~:text=clobbering%20each%20other.-,Option%202,-%3A%20Open%20as%20append

// If fileName is empty then returns and does nothing
// message1 is surrounded with single quotes in the logFile

void appendLog(const std::string& fileName, const std::string& message1 , const std::string& message2 , const std::string& message3 ) {

    if (fileName.empty()) return;   // Logging is opptional

    std::cout << "Logfile name:" << fileName << std::endl;

    // Get current time
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    // Use localtime_s for safe local time conversion
    std::tm localTime;
    localtime_s(&localTime, &time);

    // Format the date and time
    std::stringstream ss_line;
    ss_line << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S '") << message1 << "' " << message2 << " " << message3 << "\n";

    auto line = ss_line.str();

    // TODO: debug only
    std::cout << "appendLog:" << line << std::endl;

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
        std::cerr << "Failed to open the log file file handle:" << fileName << std::endl;
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

void appendLog(const std::string& fileName, const std::string& message1, const std::string& message2) {

    appendLog(fileName, message1, message2, "");

}

void appendLogFileError( std::string logFilePathStr , std::string operation , std::string filePath , int error ) {

    char errorMsg[256]; // Buffer to hold the error message

    // Use strerror_s to safely get the error message
    strerror_s(errorMsg, sizeof(errorMsg), error);

    appendLog( logFilePathStr, operation , filePath, errorMsg);

    return;
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

        appendLogFileError(logFilePathStr, "Quick Open infile", filePath, error);

        return 0;

    }

    const int ret = quickCheckOpenEmailFileForReplyTo(f, magicReplyToAddress);

    fclose(f); 

    return ret;
}

// Function to transform EML file based on specified conditions. Mostly written by ChatGPT!

// Placeholder for a hash function
const char* hash() {
    static std::string hashValue = "12345abcd";  // Example hash value
    return hashValue.c_str();
}


// Function to extract an email address from a header line or empty string if tag found in line
// Discards <>
// Writen by ChatGPT!

// We could use a regex iterator here and it would be slightly more efficient, but we are only working with a single line here so who cares.
// Also note that we quickly prescreen every file to make sure it does have a matching reply-to before we ever get here,
// so no chance that this will end up regexing over the whole body. 

std::vector<std::string> extractEmailsFromHeaderLine(const std::string& headerLine, const std::string& tagName) {
    std::vector<std::string> emailAddresses;

    // First, find the correct header and extract the relevant portion of the string
    std::regex headerRegex("^" + tagName + ":\\s*(.*)$", std::regex_constants::icase);
    std::smatch headerMatch;
    if (std::regex_search(headerLine, headerMatch, headerRegex)) {
        // If the header is found, parse out the emails
        std::string relevantPart = headerMatch[1];

        // Regex to match email addresses, possibly surrounded by names and angle brackets
        std::regex emailRegex(R"(([\w\.-]+@[\w\.-]+\.[\w\.-]+))");
        std::sregex_iterator next(relevantPart.begin(), relevantPart.end(), emailRegex);
        std::sregex_iterator end;

        // Loop through all matches and add to the vector
        while (next != end) {
            std::smatch match = *next;
            emailAddresses.push_back(match.str());
            ++next;
        }
    }

    return emailAddresses;
}

// Extract just the email address part from an RFC5322 "mailbox" which can include an option leading human name and angle braces.
// Returns all uppercase

std::string extractEmailPart(std::string mailboxName) {
    std::regex emailRegex(R"(([\w.-]+@[\w.-]+\.\w+))");  // Regular expression to match a typical email address
    std::smatch matches;

    if (std::regex_search(mailboxName, matches, emailRegex)) {

        std::string address = matches[0];

        // Convert to all uppercase
        std::transform( address.begin(), address.end(), address.begin(), ::toupper);

        return address;  // Return the first match, which should be the email
    }

    return "";  // Return an empty string if no email was found
}

// Function to transform EML file based on specified conditions
void transformEMLFile( const std::string logFileName , const std::string logDir ,  const char* filePath, 
    const char* magicReplytoEmailAddress, const char* newEmailAddressFmtString) {
    std::ifstream inFile(filePath);  // Open the original file for reading
    if (!inFile.is_open()) {
        appendLog(logFileName, "Error opening input file.", filePath);
        return;
    }

    // This must be its own line so that the string is not destroyed until the end of the block
    auto tempFilePathStr = std::string(filePath) + ".tmp";

    const char * tempFilePath = tempFilePathStr.c_str();

    std::ofstream outFile(tempFilePath); // Create a new file for writing
    if (!outFile.is_open()) {
        appendLog(logFileName, "Error opening output file.", filePath);
        inFile.close();  // Make sure to close the input file before exiting
        return;
    }

    std::vector<std::string> toAddresses;
    std::string replyToAddress;

    std::string line;

    // Read line by line from the old file looking for the to and replyto tags we need. 
    // Stops when it gets to the blank line that delimiates the headers section. 
    // The first address on the to tag will be remebreedand the header line will be copied over.
    // The first address on the replyto tag will be remembered but the header line will not be copied (we will change it and copy it later)
    // It will copy any other tags directly to the new file.

    while (std::getline(inFile, line) && !line.empty()) {

        std::vector<std::string> replyToAddresses = extractEmailsFromHeaderLine(line, "Reply-To");

        if (!replyToAddresses.empty()) {
            // TODO: Debug
            std::cout << "got reply " << replyToAddresses[0];
        }

        if (!replyToAddresses.empty()) {

            if (replyToAddresses[0] == magicReplytoEmailAddress) {

                // We found a replyto line with our magic email address
                replyToAddress = replyToAddresses[0];

            }

            // Note that we do not write the replyto tag out to the new file (yet)

        } else {

            // This header line is not a replyto tag, so check if it is a "to" tag

            std::vector<std::string> toTags = { extractEmailsFromHeaderLine(line, "To") };

            if (!toTags.empty()) {

                // TODO: Debug
                std::cout << "got to " << toTags[0] << std::endl;

                toAddresses = toTags;       // We capture all of the to's so we can record all the destinations for this replyto has
            }

            outFile << line << std::endl; // Write the line to the new file

        }

    }

    // Next we write the modified reply-to line into the outfile. 
    // We can do this here becuase the RFC says header order does not matter and we suppressed writing the orginal in code above. 

    if (!replyToAddress.empty()) {

        // There was a matching replyto header

        if (toAddresses.empty()) {

            // There was no to address. This is an unlikely edge case like a BCC
            // so we will just make up a random number.

            std::string newRandomAddressStr = generateRandomNineDigitNumberWithLeadingZeros();

            toAddresses = { newRandomAddressStr };

            // TODO: Do we need to log this? It will show up in the address lists. 
            appendLog(logFileName, "Random To", newRandomAddressStr );

            // TODO: We should get the to address from the HDR file.
            // TODO: We should process each to from the HDR seporately 

        }

        std::string toAddress = toAddresses[0];

        std::string newReplyToMailboxStr = std::string(newEmailAddressFmtString);

        // How can c++ not have a findAndReplce?
        size_t pos = newReplyToMailboxStr.find("%s");
        if (pos != std::string::npos) {
            newReplyToMailboxStr.replace(pos, 2, MakeHash(toAddress)); // Replace %s with the return value of the hash
        }

        line = "Reply-To: " + newReplyToMailboxStr; // Update the line with the new email

        outFile << line << std::endl; // Write the line to the new file

        outFile << "X-Joshreply: Processed to <" << toAddress << ">" << std::endl;

        // Here we record all of the hashed addresses in the log dir so someday we can look up an address and
        // see who we sent it to. We do it for each to on the line.

        std::string replyToAddressNormalizedStr = extractEmailPart(newReplyToMailboxStr);

        std::string toAddressLogFileName = logDir + replyToAddressNormalizedStr + ".log";

        for( std::string toAddress : toAddresses ) {
            appendLog( toAddressLogFileName , "SentTo", toAddress );
        }

    }
    else {
        outFile << "X-Joshreply: nonprocessed" << std::endl;
    }


    outFile << std::endl; // Write the blank line to the new file

    // Now copy over the rest of the lines without modification.
    // TODO: Could do this in bigger chunks for better performance. 

    while (std::getline(inFile, line)) {

        outFile << line << std::endl; // Write the line to the new file

    }

    inFile.close();
    outFile.close();

    // Delete the orginal file
    int deleteErr = remove( filePath );

    if (deleteErr) {
        appendLogFileError(logFileName, "Failed delete", filePath,  deleteErr );
        return;
    }

    // Rename the new file to the orginal file namem
    int moveErr = rename( tempFilePath , filePath);

    if (moveErr) {
        appendLogFileError(logFileName, "Failed move", tempFilePath, moveErr);
        return;
    }

}

/*

    Test with:
    D:\Github\sm-rfc-replace\sm-replychain-tools\sm-replychain-tools>for %a in (testemls\*.eml) do ..\x64\Debug\sm-replace-replyto.exe %a "josh-ac339@joshreply.com" "joshey <joshnew-%s@josh.com>" "logs/"

*/

int main( int argc , char ** argv)
{
    if (argc!=4 && argc != 5) {
        std::cout << "Expects 3 or 4 args:" << std::endl;
        std::cout << " A special replyto address string(without <>) to search for and replace" << std::endl;
        std::cout << " printf fmt string for new address (ie `joe <joe-%s>@joe.com) with %s where the hash goes" << std::endl;
        std::cout << " path to the EML file to process" << std::endl;
        std::cout << " optional path to a log directory (with trailing backslash). Must exist and must have create and append access if specified" << std::endl;
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

        // If we get here, then we passed the preliminary quick check and now we can take our time to process the email.
        std::cout << "Yes." << std::endl;

        transformEMLFile( logFileNameStr , logDirNameStr , fileName , magicReplytoAddress, replacementAddressFmtStr);

        std::cout << "end" << "\n";

    }

    return 0;

}
