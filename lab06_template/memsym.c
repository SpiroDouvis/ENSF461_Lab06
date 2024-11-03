#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>

#define TRUE 1
#define FALSE 0

// Output file
FILE* output_file;

// TLB replacement strategy (FIFO or LRU)
char* strategy;

// Physical memory
uint32_t* physical_memory;

// Flags
int define_called = FALSE;

// TLB entry structure
typedef struct {
    int pid;
    int vpn;
    int pfn;
    int valid;
} TLBEntry;

// TLB with 8 entries
TLBEntry tlb[8];

// Page table entry structure
typedef struct {
    int pfn;
    int valid;
} PageTableEntry;

// Page tables for 4 processes
PageTableEntry page_tables[4][64]; // Assuming VPN bits <= 6

// Add global current_pid for context switching
int current_pid = 0;

char** tokenize_input(char* input) {
    char** tokens = NULL;
    char* token = strtok(input, " ");
    int num_tokens = 0;

    while (token != NULL) {
        num_tokens++;
        tokens = realloc(tokens, num_tokens * sizeof(char*));
        tokens[num_tokens - 1] = malloc(strlen(token) + 1);
        strcpy(tokens[num_tokens - 1], token);
        token = strtok(NULL, " ");
    }

    num_tokens++;
    tokens = realloc(tokens, num_tokens * sizeof(char*));
    tokens[num_tokens - 1] = NULL;

    return tokens;
}

int main(int argc, char* argv[]) {
    const char usage[] = "Usage: memsym.out <strategy> <input trace> <output trace>\n";
    char* input_trace;
    char* output_trace;
    char buffer[1024];

    // Parse command line arguments
    if (argc != 4) {
        printf("%s", usage);
        return 1;
    }
    strategy = argv[1];
    input_trace = argv[2];
    output_trace = argv[3];

    // Open input and output files
    FILE* input_file = fopen(input_trace, "r");
    output_file = fopen(output_trace, "w");  

    while ( !feof(input_file) ) {
        // Read input file line by line
        char *rez = fgets(buffer, sizeof(buffer), input_file);
        if ( !rez ) {
            fprintf(stderr, "Reached end of trace. Exiting...\n");
            return -1;
        } else {
            // Remove endline character
            buffer[strlen(buffer) - 1] = '\0';
        }
        char** tokens = tokenize_input(buffer);

        if (tokens[0] == NULL || tokens[0][0] == '%') {
            // Ignore comments or empty lines
            // Deallocate tokens
            for (int i = 0; tokens[i] != NULL; i++)
                free(tokens[i]);
            free(tokens);
            continue;
        }

        if (strcmp(tokens[0], "define") == 0) {
            if (define_called) {
                fprintf(output_file, "Current PID: 0. Error: multiple calls to define in the same trace\n");
                // Deallocate tokens
                for (int i = 0; tokens[i] != NULL; i++)
                    free(tokens[i]);
                free(tokens);
                continue;
            }
            if (argc < 4) {
                fprintf(output_file, "Error: insufficient arguments for define\n");
                // Deallocate tokens
                for (int i = 0; tokens[i] != NULL; i++)
                    free(tokens[i]);
                free(tokens);
                continue;
            }
            int OFF = atoi(tokens[1]);
            int PFN = atoi(tokens[2]);
            int VPN = atoi(tokens[3]);

            // Allocate physical memory
            physical_memory = malloc((1 << (OFF + PFN)) * sizeof(uint32_t));
            for (int i = 0; i < (1 << (OFF + PFN)); i++)
                physical_memory[i] = 0;

            // Initialize TLB
            for (int i = 0; i < 8; i++) {
                tlb[i].valid = FALSE;
            }

            // Initialize page tables
            for (int pid = 0; pid < 4; pid++) {
                for (int vpn = 0; vpn < (1 << VPN); vpn++) {
                    page_tables[pid][vpn].valid = FALSE;
                }
            }

            define_called = TRUE;
            fprintf(output_file, "Current PID: 0. Memory instantiation complete. OFF bits: %d. PFN bits: %d. VPN bits: %d\n", OFF, PFN, VPN);
        }
        else {
            if (!define_called) {
                fprintf(output_file, "Current PID: 0. Error: attempt to execute instruction before define\n");
                // Deallocate tokens
                for (int i = 0; tokens[i] != NULL; i++)
                    free(tokens[i]);
                free(tokens);
                continue;
            }
            // Handle other instructions
            if (strcmp(tokens[0], "ctxswitch") == 0) {
                if (tokens[1] == NULL) {
                    fprintf(output_file, "Current PID: %d. Error: missing pid for ctxswitch\n", current_pid);
                } else {
                    int new_pid = atoi(tokens[1]);
                    if (new_pid < 0 || new_pid > 3) {
                        fprintf(output_file, "Current PID: %d. Invalid context switch to process %d\n", current_pid, new_pid);
                        // Deallocate tokens
                        for (int i = 0; tokens[i] != NULL; i++)
                            free(tokens[i]);
                        free(tokens);
                        fclose(input_file);
                        fclose(output_file);
                        free(physical_memory);
                        return -1;
                    }
                    current_pid = new_pid;
                    fprintf(output_file, "Current PID: %d. Switched execution context to process: %d\n", current_pid, current_pid);
                }
            }
            else {
                // Handle other instructions
                // TODO: Implement other instructions
            }
        }

        // Deallocate tokens
        for (int i = 0; tokens[i] != NULL; i++)
            free(tokens[i]);
        free(tokens);
    }

    // Close input and output files
    fclose(input_file);
    fclose(output_file);

    // Free physical memory
    free(physical_memory);

    return 0;
}