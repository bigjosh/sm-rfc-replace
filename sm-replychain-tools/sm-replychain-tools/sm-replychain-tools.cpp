// sm-replychain-tools.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>

#include <iostream>
#include <cstdio>
#include <cstring>
#include <string.h>
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

// This is defined by the compiler if we are compiling in debug configuration
#ifdef _DEBUG
    const BOOL debugMode = true;
#else
    const BOOL debugMode = false;
#endif

// One (match address, replacement mask, hash seed) set as given on the command line.
// The command line can carry any number of these and each outgoing email is checked against
// all of them, so you can run more than one identity through a single hook. The first set
// whose address matches the email's "Reply-To:" wins.

struct ReplyToConfig {
    std::string   magicAddress;      // Address to look for in the "Reply-To:" header (bare, no <>)
    std::string   replacementMask;   // ie "Josh Doe <new-%s@mydomain.com>" - must contain a %s
    unsigned long hashSeed;          // Seed for MakeHash(). Same type as MakeHash's parameter.
};

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
        // TODO: What else can we really do if we fail to open the log file? Maybe increment a performace counter or 
        // write to the windows event logs? https://learn.microsoft.com/en-us/troubleshoot/developer/visualstudio/cpp/language-compilers/write-entry-to-event-log
        std::cerr << "Failed to open the log file file handle:" << fileName << std::endl;
        return;
    }

    // Prepare the data to be written
    DWORD bytesWritten;

    // Write to the file
    if (!WriteFile(fileHandle, line.c_str(), static_cast<DWORD>(line.size()), &bytesWritten, NULL)) {
        // TODO: See above for fail to open
        std::cerr << "Failed to write to the file." << std::endl;
    }
    
    // Close the handle
    CloseHandle(fileHandle);
}


// Function to calculate the hash value of a string using DJB2 algorithm
static std::string MakeHash(const std::string& txt, unsigned long hashSeed) {
    unsigned long hash = hashSeed;

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


inline void debugMsg(const std::string& fileName, const std::string& message1, const std::string& message2) {

    if (debugMode) {
        appendLog(fileName, message1, message2, "");
    }

}

void appendLogFileError( std::string logFilePathStr , std::string operation , std::string filePath , int error ) {

    char errorMsg[256]; // Buffer to hold the error message

    // Use strerror_s to safely get the error message
    strerror_s(errorMsg, sizeof(errorMsg), error);

    appendLog( logFilePathStr, operation , filePath, errorMsg);

    return;
}

// Returns 1 if this line could possibly be a "Reply-To:" header holding one of our magic addresses.
// We need this to preserve the optional "name" part of the "mailbox" field.
// This is so ugly, but I think it is the fastest way when majority of lines do not match.
// Reply to address should be ni brakets like <test@test.com>
//
// This is only a prescreen, so a false positive here is harmless (it just costs us a slower
// second pass over a file we end up not changing) but a false negative would mean we silently
// skip an email we were supposed to process. So this test is deliberately LOOSER than the real
// one in findConfigForReplyToAddress() below - it is a superset of it and so cannot disagree with it.
//
// Note we test the tag once up front, so the cost per line does not grow with the number of
// configs unless the line really is a replyto header.

int checkLineReplyTo(const char* line, const std::vector<ReplyToConfig>& configs) {

    // A header field name always starts in column 0 (a "folded" continuation line starts with
    // whitespace instead), and RFC5322 says field names are case insensitive - which is why this
    // is a case insensitive compare against the front of the line rather than the strstr that
    // used to be here. The authoritative test downstream matches the tag case insensitively too,
    // so a mailer that writes "reply-to:" in lower case is no longer silently skipped.

    if (_strnicmp(line, "Reply-To:", 9) != 0) return 0;

    for (size_t nConfig = 0; nConfig < configs.size(); ++nConfig) {

        if (strstr(line, configs[nConfig].magicAddress.c_str())) return 1;

    }

    return 0;

}

// Returns the index of the config whose magic address exactly matches the address we pulled out
// of a "Reply-To:" header, or -1 if none of them do. This is the authoritative test - the
// prescreen above is a superset of it, so anything that matches here was always caught up there.

int findConfigForReplyToAddress(const std::vector<ReplyToConfig>& configs, const std::string& address) {

    for (size_t nConfig = 0; nConfig < configs.size(); ++nConfig) {

        if (address == configs[nConfig].magicAddress) return static_cast<int>(nConfig);

    }

    return -1;

}

// Had to break this out becuase c++ has no finally clause. :/

int quickCheckOpenEmailFileForReplyTo(FILE* f, const std::vector<ReplyToConfig>& configs) {

    const int maxLineLne = 1000;    // RFC5322

    char lineBuffer[maxLineLne];

    char* line;

    while ((line = fgets(lineBuffer, maxLineLne, f)) != NULL) {

        if (line[0] == '\x0d' || line[0] == '\x0a') {
            return 0;    // Reached end of headers. Emperically I checked and 0x0d alwasy comes first in SmarterMail EML files. 
        }

        if (checkLineReplyTo(line, configs)) {
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

int quickCheckEmailFileForReplyTo( std::string logFilePathStr, const char* filePath, const std::vector<ReplyToConfig>& configs) {

    FILE* f;

    errno_t error = fopen_s( &f , filePath, "rt");

    if (error != 0) {

        appendLogFileError(logFilePathStr, "Quick Open infile", filePath, error);

        return 0;

    }

    const int ret = quickCheckOpenEmailFileForReplyTo(f, configs);

    fclose(f); 

    return ret;
}

// Extract a list of email addresses from a string in RFC5322 format
// The could be stuff after the ":" in a header, or a continuation line in the case of a "folded" header
// Returns a list of plain email addresses.

std::vector<std::string> extractEmailsFromString(const std::string& s) {
    std::vector<std::string> emailAddresses;

    // Regex to match email addresses, possibly surrounded by names and angle brackets
    std::regex emailRegex(R"(([\w\.-]+@[\w\.-]+\.[\w\.-]+))");
    std::sregex_iterator next(s.begin(), s.end(), emailRegex);
    std::sregex_iterator end;

    // Loop through all matches and add to the vector
    while (next != end) {
        std::smatch match = *next;
        emailAddresses.push_back(match.str());
        ++next;
    }
    return emailAddresses;
}

// Function to extract an email address from a header line or empty string if tag found in line

std::vector<std::string> extractEmailsFromHeaderLine(const std::string& headerLine, const std::string& tagName) {
    std::vector<std::string> emailAddresses;

    // First, find the correct header and extract the relevant portion of the string
    std::regex headerRegex("^" + tagName + ":\\s*(.*)$", std::regex_constants::icase);
    std::smatch headerMatch;

    // We could use a regex iterator here and it would be slightly more efficient, but we are only working with a single line here so who cares.
    // Also note that we quickly prescreen every file to make sure it does have a matching reply-to before we ever get here,
    // so no chance that this will end up regexing over the whole body. 
    if (std::regex_search(headerLine, headerMatch, headerRegex)) {

        // If the header is found, parse out the emails
        std::string relevantPart = headerMatch[1];

        // I know the following code is almost exact dumplicate of extractEmailsFromString, but
        // it is more ceromony to convert this (char *) to a std:string than it is to duplicate the code. :/

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

// Helper function to find the last occurrence of any character from a set
// Written by chatgpt but sneeded some help. :/ 

// Helper function to find the last occurrence of any character from a set
size_t findLastOf(const std::string& str, const std::string& chars, size_t pos = std::string::npos) {
    size_t foundPos = std::string::npos;
    for (char ch : chars) {
        size_t currentPos = str.rfind(ch, pos);
        if (currentPos != std::string::npos) {


            // foundPos = (foundPos == std::string::npos) ? currentPos : std::max(foundPos, currentPos); // This does not compile under VS so the code below is a work around. 

            size_t m = currentPos;
            if (foundPos > m) {
                m = foundPos;
            }

            foundPos = (foundPos == std::string::npos) ? currentPos : m ;


        }
    }
    return foundPos;
}

// Function to extract the stem (filename without extension) from a path
std::string extractFilenameStem(const std::string& path) {
    // Find the position of the last directory separator
    size_t lastSlash = findLastOf(path, "/\\");

    // Find the start of the filename
    size_t filenameStart = (lastSlash == std::string::npos) ? 0 : lastSlash + 1;

    // Find the end of the filename (start of the extension) considering only after the last slash
    size_t lastDot = path.rfind('.');
    if (lastDot != std::string::npos && lastDot > filenameStart) {
        return path.substr(filenameStart, lastDot - filenameStart);
    }

    // If no extension found, return the whole filename
    return path.substr(filenameStart);
}

// Extract just the email address part from an RFC5322 "mailbox" which can include an option leading human name and angle braces.
// Returns all uppercase

std::string extractEmailPart(std::string mailboxName) {
    std::regex emailRegex(R"(([\w.-]+@[\w.-]+\.\w+))");  // Regular expression to match a typical email address
    std::smatch matches;

    if (std::regex_search(mailboxName, matches, emailRegex)) {

        std::string address = matches[0];

        // Convert to all uppercase
        std::transform(address.begin(), address.end(), address.begin(), ::toupper);

        return address;  // Return the first match, which should be the email
    }

    return "";  // Return an empty string if no email was found
}

// Function to transform EML file based on specified conditions
void transformEMLFile( const std::string logFileName , const std::string logDir ,  const char* filePath, 
    const std::vector<ReplyToConfig>& configs) {
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

    // Index into configs of the config whose magic address we matched, or -1 if we have not matched one.
    int matchedConfigIndex = -1;

    std::string line;

    // Read line by line from the old file looking for the to and replyto tags we need. 
    // Stops when it gets to the blank line that delimiates the headers section. 
    // The first address on the to tag will be remebreedand the header line will be copied over.
    // The first address on the replyto tag will be remembered but the header line will not be copied (we will change it and copy it later)
    // It will copy any other tags directly to the new file.

    // We need to track this since a To tag can span multipule lines via "folding"
    // Oh the unbounded complexity of parsing these RFC protocols!
    BOOL lastLineWasToTagFlag = false;

    while (std::getline(inFile, line) && !line.empty()) {

        if (lastLineWasToTagFlag && isspace(line[0])) {

            // The last line was a "to:" and this line starts with whitespace, so it is a continuation of the "to:"
            // so we need to parse any addresses on it and add them to the to list.

            auto toTags = extractEmailsFromString(line);

            // Really C++ this is the best way to append a vector to a vector?
            toAddresses.insert(toAddresses.end(), toTags.begin(), toTags.end());       // We capture all of the to's so we can record all the destinations for this replyto has

        } else {
            lastLineWasToTagFlag = false;
        }

        std::vector<std::string> replyToAddresses = extractEmailsFromHeaderLine(line, "Reply-To");

        if (!replyToAddresses.empty()) {

            lastLineWasToTagFlag = false;       // Remember that the last line was a replyto (should never becuase replyto can only be one line, but who knows?)

            const int configIndex = findConfigForReplyToAddress(configs, replyToAddresses[0]);

            if (configIndex >= 0) {

                // We found a replyto line with one of our magic email addresses.
                // Note that we do not write the replyto tag out to the new file (yet) - we write
                // our generated replacement for it below, once we know the "to" address to hash.

                matchedConfigIndex = configIndex;

            } else {

                // This is a real replyto header, just not one of ours. The prescreen above is
                // deliberately loose so this does happen. Pass the line through untouched -
                // dropping it would silently strip the sender's own replyto from the outgoing mail.

                outFile << line << std::endl;

            }

        } else {

            // This header line is not a replyto tag, so check if it is a "to" tag

            std::vector<std::string> toTags = { extractEmailsFromHeaderLine(line, "To") };

            if (!toTags.empty()) {

                // Found "To:" tag on this line

                toAddresses = toTags; // We overwrite becuase there is only allowed to be one `to:` header

                lastLineWasToTagFlag = true;        // Be ready in case this is just the begining of a "folded" header

            }

            outFile << line << std::endl; // Write the line to the new file

        }

    }

    // Next we write the modified reply-to line into the outfile. 
    // We can do this here becuase the RFC says header order does not matter and we suppressed writing the orginal in code above. 

    if (matchedConfigIndex >= 0) {

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

        // Record which of the configs fired. Handy once there is more than one of them.
        appendLog(logFileName, "Matched config", configs[matchedConfigIndex].magicAddress);

        std::string newReplyToMailboxStr = configs[matchedConfigIndex].replacementMask;

        // How can c++ not have a findAndReplce?
        size_t pos = newReplyToMailboxStr.find("%s");
        if (pos != std::string::npos) {
            newReplyToMailboxStr.replace(pos, 2, MakeHash(toAddress, configs[matchedConfigIndex].hashSeed)); // Replace %s with the return value of the hash
        }

        line = "Reply-To: " + newReplyToMailboxStr; // Update the line with the new email

        outFile << line << std::endl; // Write the line to the new file

        outFile << "X-Joshreply: Processed to <" << toAddress << ">" << std::endl;

        // Here we record all of the hashed addresses in the log dir so someday we can look up an address and
        // see who we sent it to. We do it for each to on the line.

        // Normalize the replyto address so same semantic address always ends up with same file name
        std::string replyToAddressNormalizedStr = extractEmailPart(newReplyToMailboxStr);

        std::string toAddressLogFileName = logDir + replyToAddressNormalizedStr + ".log";

        for( std::string toAddress : toAddresses ) {

            appendLog( toAddressLogFileName , "SentTo", toAddress , extractFilenameStem( filePath) );
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

// Sanity check one set of command line args before we touch any email.
// Returns an empty string if the set looks usable, otherwise a human readable reason why not.

std::string checkConfigArgs(const char* address, const char* mask, const char* seed) {

    std::string addressStr(address);
    std::string maskStr(mask);
    std::string seedStr(seed);

    // Note we want a dot in the domain as well as the "@". The regex we use to pull addresses back
    // out of the headers insists on one, so something like "magic@localhost" would pass a bare "@"
    // test here and then never be able to match anything - which would be baffling to debug.

    const size_t atPos = addressStr.find('@');

    if (atPos == std::string::npos) {
        return "match address '" + addressStr + "' does not contain an '@'";
    }

    if (addressStr.find('.', atPos) == std::string::npos) {
        return "match address '" + addressStr + "' has no '.' in its domain";
    }

    if (maskStr.find("%s") == std::string::npos) {
        return "replacement mask '" + maskStr + "' does not contain a '%s' for the hash to go into";
    }

    // Note we only check that the seed is all digits and NOT that it fits in an unsigned long.
    // See the README - seeds bigger than 4294967295 have always saturated to 4294967295 here, so
    // rejecting them now would stop an existing install dead on its next email.

    if (seedStr.empty() || seedStr.find_first_not_of("0123456789") != std::string::npos) {
        return "seed '" + seedStr + "' is not a decimal number";
    }

    return "";

}

int main( int argc , char ** argv)
{
    // The command line is...
    //
    //    exe <emlfile> <address> <mask> <seed> [<address> <mask> <seed>]... [<logdir>]
    //
    // ...so after the EML file path there are argc-2 args left over, and we can tell whether that
    // optional trailing log directory is there just by counting them:
    //
    //    (argc-2) % 3 == 0  -> all address sets, no log dir
    //    (argc-2) % 3 == 1  -> the LAST arg is the log dir, everything before it is address sets
    //    (argc-2) % 3 == 2  -> somebody miscounted, show the usage
    //
    // This keeps the old fixed forms working exactly as they always have: argc==5 is one address
    // set with no log dir, and argc==6 is one address set plus a log dir.

    const int argsAfterFile = argc - 2;

    // The argc test MUST stay first so the short circuit keeps argsAfterFile from going negative
    // before we take the modulo. C++ says -1 % 3 == -1, which would sneak straight past the == 2.

    if (argc < 5 || (argsAfterFile % 3) == 2) {
        std::cout << "Expects an EML file path, then one or more (address, mask, seed) sets, then an optional log dir:" << std::endl;
        std::cout << "  arg 1        : path to the EML file to process (SmarterMail passes %filepath here)" << std::endl;
        std::cout << "  args 2,5,8...: a special replyto address string (without <>) to search for and replace" << std::endl;
        std::cout << "  args 3,6,9...: printf fmt string for the new address (ie \"joe <joe-%s@joe.com>\") with %s where the hash goes" << std::endl;
        std::cout << "  args 4,7,10..: seed for generating reply to hashes (decimal digits, unsigned long)" << std::endl;
        std::cout << "  last arg     : optional path to a log directory (with trailing backslash). Must exist and must have create and append access if specified" << std::endl;
        std::cout << "Example with two address sets:" << std::endl;
        std::cout << "  sm-replace-replyto.exe %filepath \"work@example.com\" \"Josh <w-%s@example.com>\" 1234567 \"home@example.com\" \"Josh <h-%s@other.com>\" 7654321 \"g:/logs/\"" << std::endl;
        return 0; 
    }
    std::cout << "begin" << std::endl;

    const char* fileName    = argv[1];
    const int   configCount = argsAfterFile / 3;            // The integer divide drops the optional log dir
    const bool  haveLogDir  = ((argsAfterFile % 3) == 1);

    // These default to empty
    std::string logDirNameStr;
    std::string logFileNameStr;

    // Work out the log dir before we parse the address sets so that a bad set can actually be logged.

    if (haveLogDir) {
        logDirNameStr = argv[argc - 1];
        logFileNameStr = logDirNameStr + "log.txt";
    }

    debugMsg(logFileNameStr, "Start. argc=", std::to_string( argc ) );

    if (haveLogDir) {
        debugMsg(logFileNameStr, "Logging on.", "");
    }

    std::vector<ReplyToConfig> configs;

    for (int nConfig = 0; nConfig < configCount; ++nConfig) {

        const char* addressArg = argv[2 + (nConfig * 3) + 0];
        const char* maskArg    = argv[2 + (nConfig * 3) + 1];
        const char* seedArg    = argv[2 + (nConfig * 3) + 2];

        const std::string problem = checkConfigArgs(addressArg, maskArg, seedArg);

        if (!problem.empty()) {

            // Bad args. Complain loudly and bail out WITHOUT touching the email at all - it is much
            // better to send the mail through unmodified than to rewrite it using a config we do
            // not understand. Note we still exit 0 because it is not documented what SmarterMail
            // does with a non zero exit code from the command line hook, and we do not want to risk
            // it holding or failing the message. The log line is how you find out.

            const std::string where = "BAD CONFIG in address set #" + std::to_string(nConfig + 1);

            std::cerr << where << ": " << problem << std::endl;
            appendLog(logFileNameStr, where, problem, fileName);

            return 0;

        }

        ReplyToConfig config;

        config.magicAddress    = addressArg;
        config.replacementMask = maskArg;
        config.hashSeed        = strtoul(seedArg, NULL, 10);

        configs.push_back(config);

    }

    const std::string configCountStr = std::to_string(configs.size()) + " address set(s)";

    if (!quickCheckEmailFileForReplyTo(  logFileNameStr, fileName, configs)) {
        debugMsg(logFileNameStr, "No match.", configCountStr );
    } else {

        // If we get here, then we passed the preliminary quick check and now we can take our time to process the email.
        debugMsg(logFileNameStr, "Match." , configCountStr);
        appendLog(logFileNameStr, "Process", fileName);
        transformEMLFile( logFileNameStr , logDirNameStr , fileName , configs);

    }

    return 0;

}
