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

    // another check to see if md5() failed to allocate memory or compute the hash
    if (!plainHash) {
        return NULL;
    }

    // Open the hash file 
    FILE *hashFile = fopen(hashFilename, "r");
    
    // if the hash file doesn't open successfully
    if (!hashFile) {
        // free md5 before returning
        free(plainHash);
        return NULL;

    }

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
            // free the md5 result
            free(plainHash);
            // return the found hash
            return ret;
        }
    }

    // if not found, close file, free md5 string, and return NULL.
    fclose(hashFile);
    free(plainHash);
    return NULL;
}

// main function, check the command line arguments for proper usage, opens the dictionary file
// and reads it line by line and sends each word to tryWord() to check against the hashes
// and prints any cracked hashes with their corresponding word and counts
// as well as displays how many hashes were cracked
int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // Open the dictionary file for reading.
    FILE *dictFile = fopen(argv[2], "r");
    
    // if the dictionary file doesn't open successfully
    if (!dictFile)
    {
        fprintf(stderr, "error: could not open dictionary file %s\n", argv[2]);
        exit(1);
    }

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    char word[PASS_LEN + 2];
    int cracked = 0;

    while (fgets(word, sizeof(word), dictFile))
    {
        // remove newline or carriage return characters
        size_t L = strlen(word);
        while (L > 0 && (word[L - 1] == '\n' || word[L - 1] == '\r'))
        {
            word[--L] = '\0';
        }
        
        if (L == 0) continue; // skip empty lines

        // send word to tryWord to see if it matches any hash
        char *match = tryWord(word, argv[1]);

        // If we got a match, display the hash and the word.
        if (match)
        {
            // print the hash and the corresponding word
            printf("%s %s\n", match, word);
            free(match); // free returned string
            cracked++;   // increase cracked counter
        }
    }

    // Close the dictionary file.
    fclose(dictFile);
    
    // Display the number of hashes that were cracked.
    printf("%d Hashes Cracked!\n", cracked);

    // Free up any malloc'd memory?
    return 0;
}