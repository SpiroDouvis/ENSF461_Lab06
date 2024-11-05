#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>

#define TRUE 1
#define FALSE 0

// Output file
FILE *output_file;

// TLB replacement strategy (FIFO or LRU)
char *strategy;

// Physical memory
uint32_t *physical_memory;

// Flags
int define_called = FALSE;

// TLB entry structure
typedef struct
{
    int pid;
    int vpn;
    int pfn;
    int valid;

    uint32_t timestamp;     // ADDED FOR LRU
} TLBEntry;

// TLB with 8 entries
TLBEntry tlb[8];

// Page table entry structure
typedef struct
{
    int pfn;
    int valid;
} PageTableEntry;

// Page tables for 4 processes
PageTableEntry page_tables[4][64]; // Assuming VPN bits <= 6

// Add global current_pid for context switching
int current_pid = 0;

// TLB Replacement Index for FIFO
int tlb_next_replace_index = 0;

// Registers for 4 processes
int r1[4] = {0};
int r2[4] = {0};

// Define OFF_BITS_defined and VPN_BITS_defined as global variables
int OFF_BITS_defined = 4;
int VPN_BITS_defined = 6;

uint32_t timestamp;

// Function to tokenize input
char **tokenize_input(char *input)
{
    char **tokens = NULL;
    char *token = strtok(input, " ");
    int num_tokens = 0;

    while (token != NULL)
    {
        num_tokens++;
        tokens = realloc(tokens, num_tokens * sizeof(char *));
        tokens[num_tokens - 1] = malloc(strlen(token) + 1);
        strcpy(tokens[num_tokens - 1], token);
        token = strtok(NULL, " ");
    }

    num_tokens++;
    tokens = realloc(tokens, num_tokens * sizeof(char *));
    tokens[num_tokens - 1] = NULL;

    return tokens;
}

// Helper function to translate virtual address to physical address
int translate_address(int address, int *pfn_out, int *tlb_index_out, int *hit_out)
{
    // Use global OFF_BITS_defined and VPN_BITS_defined
    int VPN = (address >> OFF_BITS_defined) & ((1 << VPN_BITS_defined) - 1);
    int offset = address & ((1 << OFF_BITS_defined) - 1);

    // TLB Lookup
    for (int i = 0; i < 8; i++)
    {
        if (tlb[i].valid && tlb[i].pid == current_pid && tlb[i].vpn == VPN)
        {
            *pfn_out = tlb[i].pfn;
            *tlb_index_out = i;
            *hit_out = TRUE;

            if (strcmp(strategy, "LRU")==0)
                tlb[i].timestamp = timestamp; 

            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d hit in TLB entry %d. PFN is %d\n",
                    current_pid, VPN, i, tlb[i].pfn);
            return 1; // Success
        }
    }

    // TLB Miss
    *hit_out = FALSE;
    fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d caused a TLB miss\n", current_pid, VPN);

    // Check page table
    if (!page_tables[current_pid][VPN].valid)
    {
        fprintf(output_file, "Current PID: %d. Translating. Translation for VPN %d not found in page table\n", current_pid, VPN);
        return 0; // Translation not found
    }

    *pfn_out = page_tables[current_pid][VPN].pfn;

    // DDED-Update TLB using FIFO or LRU 
    int replace_index = 0;
    if (strcmp(strategy, "FIFO")==0)    //if FIFO
    {
        replace_index = tlb_next_replace_index;
        tlb_next_replace_index = (tlb_next_replace_index + 1) % 8;
    }
    else if (strcmp(strategy, "LRU")==0)    //if LRU
    {
        uint32_t min_timestamp = UINT32_MAX;
        for (int i=0;i<8;i++)
        {
            if(!tlb[i].valid)
            {
                replace_index=i;
                break;
            }
            if (tlb[i].timestamp<min_timestamp)
            {
                min_timestamp=tlb[i].timestamp;
                replace_index=i;
            }
        }
    }

    // Update TLB using FIFO
    // tlb[tlb_next_replace_index].pid = current_pid;
    // tlb[tlb_next_replace_index].vpn = VPN;
    // tlb[tlb_next_replace_index].pfn = *pfn_out;
    // tlb[tlb_next_replace_index].valid = TRUE;
    // int replaced_index = tlb_next_replace_index;
    // tlb_next_replace_index = (tlb_next_replace_index + 1) % 8;

    tlb[replace_index].pid = current_pid;
    tlb[replace_index].vpn = VPN;
    tlb[replace_index].pfn = *pfn_out;
    tlb[replace_index].valid = TRUE;
    // tlb[replace_index].timestamp = timestamp++;

    fprintf(output_file, "Current PID: %d. Translating. Successfully mapped VPN %d to PFN %d\n", current_pid, VPN, *pfn_out);

    *tlb_index_out = replace_index;

    return 1; // Success
}

int main(int argc, char *argv[])
{
    timestamp = 0;

    const char usage[] = "Usage: memsym.out <strategy> <input trace> <output trace>\n";
    char *input_trace;
    char *output_trace;
    char buffer[1024];

    // Parse command line arguments
    if (argc != 4)
    {
        printf("%s", usage);
        return 1;
    }
    strategy = argv[1];
    input_trace = argv[2];
    output_trace = argv[3];

    // Open input and output files
    FILE *input_file = fopen(input_trace, "r");
    if (input_file == NULL)
    {
        fprintf(stderr, "Error opening input file.\n");
        return 1;
    }
    output_file = fopen(output_trace, "w");
    if (output_file == NULL)
    {
        fprintf(stderr, "Error opening output file.\n");
        fclose(input_file);
        return 1;
    }

    while (!feof(input_file))
    {
        // Read input file line by line
        char *rez = fgets(buffer, sizeof(buffer), input_file);
        if (!rez)
        {
            // Reached end of file
            break;
        }
        else
        {
            // Remove endline character
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n')
            {
                buffer[len - 1] = '\0';
            }
        }

        char **tokens = tokenize_input(buffer);

        if (tokens[0] == NULL || tokens[0][0] == '%')
        {
            // Ignore comments or empty lines
            for (int i = 0; tokens[i] != NULL; i++)
            {
                free(tokens[i]);
            }

            free(tokens);
            continue;
        }
        timestamp++;
        if (strcmp(tokens[0], "define") == 0)
        {
            if (define_called)
            {
                fprintf(output_file, "Current PID: %d. Error: multiple calls to define in the same trace\n", current_pid);
                for (int i = 0; tokens[i] != NULL; i++)
                    free(tokens[i]);
                free(tokens);
                continue;
            }
            if (argc < 4)
            {
                fprintf(output_file, "Error: insufficient arguments for define\n");
                for (int i = 0; tokens[i] != NULL; i++)
                {
                    free(tokens[i]);
                }
                free(tokens);
                continue;
            }
            int OFF = atoi(tokens[1]);
            int PFN = atoi(tokens[2]);
            int VPN = atoi(tokens[3]);

            // Set global OFF_BITS_defined and VPN_BITS_defined
            OFF_BITS_defined = OFF;
            VPN_BITS_defined = VPN;

            // Allocate physical memory
            physical_memory = malloc((1 << (OFF + PFN)) * sizeof(uint32_t));
            if (physical_memory == NULL)
            {
                fprintf(stderr, "Error allocating physical memory.\n");
                for (int i = 0; tokens[i] != NULL; i++)
                    free(tokens[i]);
                free(tokens);
                fclose(input_file);
                fclose(output_file);
                return 1;
            }
            for (int i = 0; i < (1 << (OFF + PFN)); i++)
                physical_memory[i] = 0;

            // Initialize TLB
            for (int i = 0; i < 8; i++)
            {
                tlb[i].valid = FALSE;
                tlb[i].pfn = 0;

            }
            tlb_next_replace_index = 0; // Reset TLB replacement index

            // Initialize page tables
            for (int pid = 0; pid < 4; pid++)
            {
                for (int vpn = 0; vpn < (1 << VPN_BITS_defined); vpn++)
                {
                    page_tables[pid][vpn].valid = FALSE;
                }
            }

            define_called = TRUE;
            fprintf(output_file, "Current PID: %d. Memory instantiation complete. OFF bits: %d. PFN bits: %d. VPN bits: %d\n",
                current_pid, OFF_BITS_defined, PFN, VPN_BITS_defined);
        }

        else
        {
            if (!define_called)
            {
                fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", current_pid);
                // Free tokens
                for (int i = 0; tokens[i] != NULL; i++)
                {
                    free(tokens[i]);
                }
                free(tokens);

                // Clean up and terminate the program
                fclose(input_file);
                fclose(output_file);
                free(physical_memory);
                return -1; // Exit with an error code
            }

            // Handle other instructions
            if (strcmp(tokens[0], "ctxswitch") == 0)
            {
                if (tokens[1] == NULL)
                {
                    fprintf(output_file, "Current PID: %d. Error: missing pid for ctxswitch\n", current_pid);
                }
                else
                {
                    int new_pid = atoi(tokens[1]);
                    if (new_pid < 0 || new_pid > 3)
                    {
                        fprintf(output_file, "Current PID: %d. Invalid context switch to process %d\n", current_pid, new_pid);
                        // Clean up and terminate
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
            else if (strcmp(tokens[0], "map") == 0)
            {
                if (tokens[1] == NULL || tokens[2] == NULL)
                {
                    fprintf(output_file, "Current PID: %d. Error: insufficient arguments for map\n", current_pid);
                }
                else
                {
                    int VPN = atoi(tokens[1]);
                    int PFN = atoi(tokens[2]);

                    // Update page table
                    page_tables[current_pid][VPN].pfn = PFN;
                    page_tables[current_pid][VPN].valid = TRUE;

                    // Update TLB
                    int found = FALSE;
                    for (int i = 0; i < 8; i++)
                    {
                        if (tlb[i].valid && tlb[i].pid == current_pid && tlb[i].vpn == VPN)
                        {
                            tlb[i].pfn = PFN;

                            // tlb[i].timestamp = timestamp++; 
                            tlb[i].timestamp = timestamp; 
                            
                            found = TRUE;
                            break;
                        }
                    }
                    if (!found)
                    {
                        // Find an invalid TLB entry
                        int inserted = FALSE;
                        for (int i = 0; i < 8; i++)
                        {
                            if (!tlb[i].valid)
                            {
                                tlb[i].pid = current_pid;
                                tlb[i].vpn = VPN;
                                tlb[i].pfn = PFN;
                                tlb[i].valid = TRUE;

                                // tlb[i].timestamp = timestamp++; // ADDED FOR LRU
                                tlb[i].timestamp = timestamp; // ADDED FOR LRU

                                inserted = TRUE;
                                break;
                            }
                        }
                        if (!inserted)
                        {
                           // ADDED - Replace using FIFO or LRU
                            int replace_index=0;
                            if (strcmp(strategy, "FIFO")==0)    // if FIFO
                            {
                                replace_index = tlb_next_replace_index;
                                tlb_next_replace_index = (tlb_next_replace_index + 1) % 8;
                            }
                            else if (strcmp(strategy, "LRU")==0)    // if LRU
                            {
                                uint32_t min_timestamp = UINT32_MAX;
                                for (int i = 0; i < 8; i++)
                                {
                                    if (tlb[i].timestamp < min_timestamp)
                                    {
                                        min_timestamp = tlb[i].timestamp;
                                        replace_index = i;
                                    }
                                }
                            }

                            tlb[replace_index].pid = current_pid;
                            tlb[replace_index].vpn = VPN;
                            tlb[replace_index].pfn = PFN;
                            tlb[replace_index].valid = TRUE;
                            // tlb[replace_index].timestamp = timestamp; // for LRU
                            tlb[replace_index].timestamp = timestamp++; // for LRU

                            // // Replace using FIFO
                            // tlb[tlb_next_replace_index].pid = current_pid;
                            // tlb[tlb_next_replace_index].vpn = VPN;
                            // tlb[tlb_next_replace_index].pfn = PFN;
                            // tlb[tlb_next_replace_index].valid = TRUE;
                            // tlb_next_replace_index = (tlb_next_replace_index + 1) % 8;
                        }
                    }

                    fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n",
                            current_pid, VPN, PFN);
                }
            }
            else if (strcmp(tokens[0], "unmap") == 0)
            {
                if (tokens[1] == NULL)
                {
                    fprintf(output_file, "Current PID: %d. Error: missing VPN for unmap\n", current_pid);
                }
                else
                {
                    int VPN = atoi(tokens[1]);

                    // Update page table
                    page_tables[current_pid][VPN].valid = FALSE;
                    page_tables[current_pid][VPN].pfn = 0;


                    // Update TLB
                    for (int i = 0; i < 8; i++)
                    {
                        if (tlb[i].valid && tlb[i].pid == current_pid && tlb[i].vpn == VPN)
                        {
                            tlb[i].valid = FALSE;
                            tlb[i].pfn = 0;
                            break;
                        }
                    }

                    fprintf(output_file, "Current PID: %d. Unmapped virtual page number %d\n", current_pid, VPN);
                }
            }
            else if (strcmp(tokens[0], "load") == 0)
            {
                if (tokens[1] == NULL || tokens[2] == NULL)
                {
                    fprintf(output_file, "Current PID: %d. Error: insufficient arguments for load\n", current_pid);
                }
                else
                {
                    char *dst_reg = tokens[1];
                    char *src = tokens[2];
                    int *dst = NULL;

                    // Validate destination register
                    if (strcmp(dst_reg, "r1") == 0)
                    {
                        dst = &r1[current_pid];
                    }
                    else if (strcmp(dst_reg, "r2") == 0)
                    {
                        dst = &r2[current_pid];
                    }
                    else
                    {
                        fprintf(output_file, "Current PID: %d. Error: invalid register operand %s\n", current_pid, dst_reg);
                        // Clean up and terminate
                        for (int i = 0; tokens[i] != NULL; i++)
                            free(tokens[i]);
                        free(tokens);
                        fclose(input_file);
                        fclose(output_file);
                        free(physical_memory);
                        return -1;
                    }

                    if (src[0] == '#')
                    {
                        // Immediate value
                        int immediate = atoi(src + 1);
                        *dst = immediate;
                        fprintf(output_file, "Current PID: %d. Loaded immediate %d into register %s\n",
                                current_pid, immediate, dst_reg);
                    }
                    else
                    {
                        // Memory location
                        int address = atoi(src);
                        int PFN, tlb_index;
                        int hit;

                        // Translate address
                        int translation_success = translate_address(address, &PFN, &tlb_index, &hit);
                        if (translation_success)
                        {
                            // Calculate physical address using global OFF_BITS_defined
                            int physical_address = (PFN << OFF_BITS_defined) | (address & ((1 << OFF_BITS_defined) - 1));
                            if (physical_address < (1 << (OFF_BITS_defined + VPN_BITS_defined)))
                            { // Ensure within allocated memory
                                int value = physical_memory[physical_address];
                                *dst = value;
                                fprintf(output_file, "Current PID: %d. Loaded value of location %d (%d) into register %s\n",
                                        current_pid, address, value, dst_reg);
                            }
                            else
                            {
                                fprintf(output_file, "Current PID: %d. Error: physical address %d out of bounds\n", current_pid, physical_address);
                                // Clean up and terminate
                                for (int i = 0; tokens[i] != NULL; i++)
                                    free(tokens[i]);
                                free(tokens);
                                fclose(input_file);
                                fclose(output_file);
                                free(physical_memory);
                                return -1;
                            }
                        }
                        else
                        {
                            // Translation failed
                            // fprintf(output_file, "Current PID: %d. Error: translation failed for address %d\n", current_pid, address);
                            // fclose(input_file);
                            // fclose(output_file);
                            // free(physical_memory);
                            // return -1;
                        }
                    }
                }
            }
            else if (strcmp(tokens[0], "store") == 0)
            {
                if (tokens[1] == NULL || tokens[2] == NULL)
                {
                    fprintf(output_file, "Current PID: %d. Error: insufficient arguments for store\n", current_pid);
                }
                else
                {
                    char *dst_mem = tokens[1];
                    char *src = tokens[2];
                    int value_to_store = 0;
            
                    if (src[0] == 'r')
                    {
                        // Register source
                        if (strcmp(src, "r1") == 0)
                        {
                            value_to_store = r1[current_pid];
                        }
                        else if (strcmp(src, "r2") == 0)
                        {
                            value_to_store = r2[current_pid];
                        }
                        else
                        {
                            fprintf(output_file, "Current PID: %d. Error: invalid register operand %s\n", current_pid, src);
                            // Clean up and terminate
                            for (int i = 0; tokens[i] != NULL; i++)
                                free(tokens[i]);
                            free(tokens);
                            fclose(input_file);
                            fclose(output_file);
                            free(physical_memory);
                            return -1;
                        }
            
                        // Convert dst_mem to address
                        int address = atoi(dst_mem);
                        int PFN, tlb_index;
                        int hit;
            
                        // Translate address
                        int translation_success = translate_address(address, &PFN, &tlb_index, &hit);
                        if (translation_success)
                        {
                            // Calculate physical address using global OFF_BITS_defined
                            int physical_address = (PFN << OFF_BITS_defined) | (address & ((1 << OFF_BITS_defined) - 1));
                            if (physical_address < (1 << (OFF_BITS_defined + VPN_BITS_defined)))
                            { // Ensure within allocated memory
                                physical_memory[physical_address] = value_to_store;
                                fprintf(output_file, "Current PID: %d. Stored value of register %s (%d) into location %s\n",
                                        current_pid, src, value_to_store, dst_mem);
                            }
                            else
                            {
                                fprintf(output_file, "Current PID: %d. Error: physical address %d out of bounds\n", current_pid, physical_address);
                                // Clean up and terminate
                                for (int i = 0; tokens[i] != NULL; i++)
                                    free(tokens[i]);
                                free(tokens);
                                fclose(input_file);
                                fclose(output_file);
                                free(physical_memory);
                                return -1;
                            }
                        }
                        else
                        {
                            fprintf(output_file, "Current PID: %d. Error: translation failed for address %d\n", current_pid, address);
                            fclose(input_file);
                            fclose(output_file);
                            free(physical_memory);
                            return -1;
                        }
                    }
                    else if (src[0] == '#')
                    {
                        // Immediate value
                        value_to_store = atoi(src + 1);

                        
                        // Implement translation and storage if needed (optional based on requirements)
                        // If immediate values need to be stored in memory, uncomment the following:
            
                        
                        int address = atoi(dst_mem);
                        int PFN, tlb_index;
                        int hit;
            
                        // Translate address
                        int translation_success = translate_address(address, &PFN, &tlb_index, &hit);
                        if (translation_success)
                        {
                            // Calculate physical address using global OFF_BITS_defined
                            int physical_address = (PFN << OFF_BITS_defined) | (address & ((1 << OFF_BITS_defined) - 1));
                            if (physical_address < (2 << (OFF_BITS_defined + VPN_BITS_defined)))
                            { // Ensure within allocated memory
                                // tlb[tlb_index].timestamp = timestamp;
                                physical_memory[physical_address] = value_to_store;
                                fprintf(output_file, "Current PID: %d. Stored immediate %d into location %s\n",
                                        current_pid, value_to_store, dst_mem);
                            }
                            else
                            {
                                fprintf(output_file, "Current PID: %d. Error: physical address %d out of bounds\n", current_pid, physical_address);
                                // Clean up and terminate
                            }
                        }
                        else
                        {
                            fprintf(output_file, "Current PID: %d. Error: translation failed for address %d\n", current_pid, address);
                        }
                        
                    }
                    else
                    {
                        // Memory location (Not implemented yet)
                        fprintf(output_file, "Current PID: %d. Error: store from memory location not implemented\n", current_pid);
                    }
                }
            }
            else if (strcmp(tokens[0], "add") == 0)
            {
                // Perform the addition: r1 = r1 + r2
                r1[current_pid] += r2[current_pid];

                // Output the result
                fprintf(output_file, "Current PID: %d. Added contents of registers r1 (%d) and r2 (%d). Result: %d\n",
                        current_pid, r1[current_pid] - r2[current_pid], r2[current_pid], r1[current_pid]);
            }
            else if (strcmp(tokens[0], "rinspect") == 0) {
                if (tokens[1] == NULL)
                {
                    fprintf(output_file, "Current PID: %d. Error: missing register for rinspect\n", current_pid);
                }
                else
                {
                    char *reg = tokens[1];
                    int *value = NULL;

                    // Validate register
                    if (strcmp(reg, "r1") == 0)
                    {
                        value = &r1[current_pid];
                    }
                    else if (strcmp(reg, "r2") == 0)
                    {
                        value = &r2[current_pid];
                    }
                    else
                    {
                        fprintf(output_file, "Current PID: %d. Error: invalid register operand %s\n", current_pid, reg);
                        // Clean up and terminate
                        for (int i = 0; tokens[i] != NULL; i++)
                            free(tokens[i]);
                        free(tokens);
                        fclose(input_file);
                        fclose(output_file);
                        free(physical_memory);
                        return -1;
                    }

                    fprintf(output_file, "Current PID: %d. Inspected register %s. Content: %d\n", current_pid, reg, *value);
                }
            }
            else if (strcmp(tokens[0], "pinspect") == 0) {
                if (tokens[1] == NULL)
                {
                    fprintf(output_file, "Current PID: %d. Error: missing VPN for pinspect\n", current_pid);
                }
                else
                {
                    int VPN = atoi(tokens[1]);

                    // Validate VPN
                    if (VPN < 0 || VPN >= (1 << VPN_BITS_defined))
                    {
                        fprintf(output_file, "Current PID: %d. Error: invalid VPN %d\n", current_pid, VPN);
                        // Clean up and terminate
                        for (int i = 0; tokens[i] != NULL; i++)
                            free(tokens[i]);
                        free(tokens);
                        fclose(input_file);
                        fclose(output_file);
                        free(physical_memory);
                        return -1;
                    }

                    // Output the page table entry
                    fprintf(output_file, "Current PID: %d. Inspected page table entry %d. Physical frame number: %d. Valid: %d\n",
                            current_pid, VPN, page_tables[current_pid][VPN].pfn, page_tables[current_pid][VPN].valid);
                }
            }
            else if (strcmp(tokens[0], "linspect") == 0) {
                if (tokens[1] == NULL)
                {
                    fprintf(output_file, "Current PID: %d. Error: missing physical location for linspect\n", current_pid);
                }
                else
                {
                    int physical_location = atoi(tokens[1]);

                    // Validate physical location
                    if (physical_location < 0 || physical_location >= (1 << (OFF_BITS_defined + VPN_BITS_defined)))
                    {
                        fprintf(output_file, "Current PID: %d. Error: invalid physical location %d\n", current_pid, physical_location);
                        // Clean up and terminate
                        for (int i = 0; tokens[i] != NULL; i++)
                            free(tokens[i]);
                        free(tokens);
                        fclose(input_file);
                        fclose(output_file);
                        free(physical_memory);
                        return -1;
                    }

                    // Output the content of the memory word at the physical location
                    fprintf(output_file, "Current PID: %d. Inspected physical location %d. Value: %d\n",
                            current_pid, physical_location, physical_memory[physical_location]);
                }

            }
            else if (strcmp(tokens[0], "tinspect") == 0) {
                if (tokens[1] == NULL)
                {
                    fprintf(output_file, "Current PID: %d. Error: missing TLBN for tinspect\n", current_pid);
                }
                else
                {
                    int TLBN = atoi(tokens[1]);

                    // Validate TLBN
                    if (TLBN < 0 || TLBN >= 8)
                    {
                        fprintf(output_file, "Current PID: %d. Error: invalid TLBN %d\n", current_pid, TLBN);
                        // Clean up and terminate
                        for (int i = 0; tokens[i] != NULL; i++)
                            free(tokens[i]);
                        free(tokens);
                        fclose(input_file);
                        fclose(output_file);
                        free(physical_memory);
                        return -1;
                    }

                    // Output the content of the TLB entry
                    fprintf(output_file, "Current PID: %d. Inspected TLB entry %d. VPN: %d. PFN: %d. Valid: %d. PID: %d. Timestamp: %d\n",
                            current_pid, TLBN, tlb[TLBN].vpn, tlb[TLBN].pfn, tlb[TLBN].valid, tlb[TLBN].pid, tlb[TLBN].timestamp);
                }
            }
            else
            {
                // Handle other instructions
                fprintf(output_file, "Current PID: %d. Error: Unknown instruction '%s'\n", current_pid, tokens[0]);
            }

            // Free tokens after processing each instruction
            for (int i = 0; tokens[i] != NULL; i++)
            {
                free(tokens[i]);
            }
            free(tokens);
        }
    }
    // Close input and output files after processing all instructions
    fclose(input_file);
    fclose(output_file);

    // Free physical memory
    free(physical_memory);

    return 0;
}