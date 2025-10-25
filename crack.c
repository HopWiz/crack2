#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *plainHash = md5(plaintext, strlen(plaintext));

    // Open the hash file 
    FILE *hashFile = fopen(hashFilename, "r");
    if (!hashFile) return NULL;

    // Loop through the hash file, one line at a time.
    char line[HASH_LEN];
    while (fgets(line, sizeof(line), hashFile) != NULL) {
        // strip newline/carriage return
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) {
            line[--n] = '\0';
        }

        // Attempt to match the hash from the file to the
        // hash of the plaintext
        if (strcmp(line, plainHash) == 0) {
            // if there is a match, return the hash.
            char *ret = (char *)malloc(HASH_LEN);
            if (ret) {
                strcpy(ret, line);
            }
            
            // before returning, close the opened file
            fclose(hashFile);
            // return the found hash
            return ret;
        }
    }

    // if not found, close file and return NULL.
    fclose(hashFile);
    return NULL;
}

// main function, chekc the command line arguments for proper usage, tests tryWord() using the word "hello" 
// 
int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // These two lines exist for testing. When you have
    // tryWord working, it should display the hash for "hello",
    // which is 5d41402abc4b2a76b9719d911017c592.
    // Then you can remove these twolines and complete the rest
    // of the main function below.
    char *found = tryWord("hello", "hashes00.txt");
    printf("%s %s\n", found, "hello");


    // Open the dictionary file for reading.

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    
    // If we got a match, display the hash and the word. For example:
    //   5d41402abc4b2a76b9719d911017c592 hello
    
    // Close the dictionary file.

    // Display the number of hashes that were cracked.
    
    // Free up any malloc'd memory?
}

