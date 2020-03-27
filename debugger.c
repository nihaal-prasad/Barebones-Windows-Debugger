#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<processthreadsapi.h>
#include<minwinbase.h>
#include<windows.h>
#include<debugapi.h>
#include<dbghelp.h>
#include<winnt.h>

// Contains information for a single breakpoint (used as a linked list)
typedef struct _breakpoint {
    char byte; // Contains the byte that will be overwritten with INT 3
    struct _breakpoint *next; // Contains the next value in the linked list
    void *addr; // Contains the address that the breakpoint is at
} Breakpoint;
static Breakpoint *head = NULL; // Head of the linked list of breakpoints
static CREATE_PROCESS_DEBUG_INFO pInfo = {0}; // Contains information about the process creation
static PROCESS_INFORMATION pi = {0}; // Contains information about the debugged process
static int dwContinueStatus = DBG_CONTINUE; // The status for continuing execution
static char cont = 1; // This is set to 0 when the debugger exits

// Allocates memory on the heap
void *mymalloc(int size) {
    void *mem = malloc(size);
    if(mem == NULL) {
        printf("Error allocating memory on the heap.");
        exit(0);
    }
    return mem;
}

// Prints out all of the values of the registers
void PrintRegs() {
    // Read the registers
    CONTEXT lcContext;
    lcContext.ContextFlags = CONTEXT_ALL;
    GetThreadContext(pInfo.hThread, &lcContext);
    
    // Print out all of the values of the registers
    printf("RAX: 0x%llx\n", lcContext.Rax);
    printf("RBX: 0x%llx\n", lcContext.Rbx);
    printf("RCX: 0x%llx\n", lcContext.Rcx);
    printf("RDX: 0x%llx\n", lcContext.Rdx);
    printf("RSP: 0x%llx\n", lcContext.Rsp);
    printf("RBP: 0x%llx\n", lcContext.Rbp);
    printf("RSI: 0x%llx\n", lcContext.Rsi);
    printf("RDI: 0x%llx\n", lcContext.Rdi);
    printf("R8: 0x%llx\n", lcContext.R8);
    printf("R9: 0x%llx\n", lcContext.R9);
    printf("R10: 0x%llx\n", lcContext.R10);
    printf("R11: 0x%llx\n", lcContext.R11);
    printf("R12: 0x%llx\n", lcContext.R12);
    printf("R13: 0x%llx\n", lcContext.R13);
    printf("R14: 0x%llx\n", lcContext.R14);
    printf("R15: 0x%llx\n", lcContext.R15);
    printf("RIP: 0x%llx\n", lcContext.Rip);
}

// Adds a breakpoint to the linked list of breakpoints
void AddBreakpoint(void *addr) {
    // Create space on the heap for this breakpoint
    Breakpoint *b = mymalloc(sizeof(Breakpoint));
    b->addr = addr;

    // Get the byte that we want to replace with INT 3 and store it in b.byte
    ReadProcessMemory(pInfo.hProcess, addr, &(b->byte), 1, NULL);

    // Insert an INT 3 (0xCC) instruction
    char byte = 0xCC;
    WriteProcessMemory(pInfo.hProcess, addr, &byte, 1, NULL);
    FlushInstructionCache(pInfo.hProcess, addr, 1);

    // Insert this into the linked list
    b->next = head;
    head = b;
}

// Reads n bytes from the given memory address
void ReadMemory(char *addr_hex, int n) {
    // Convert the address from a hex string into a DWORD64
    long long addr = strtoll(addr_hex, 0, 16);
    printf("Reading memory from address 0x%llx...\n", addr);

    // Read n bytes from the given memory address
    char *buf = mymalloc(n);
    ReadProcessMemory(pInfo.hProcess, (LPCVOID) addr, buf, n, NULL);

    // Loop through each byte in the buffer and print it out
    for(int i = 0; i < n; i++) {
        printf("0x%x ", buf[i]);
    }
    printf("\n");
}

// Allows the user to type in commands into the debugger
void ProcessCommands() {
    char *cmd = mymalloc(200); // The command that the user types in
    while(strncmp(cmd, "continue", 8) != 0 && strncmp(cmd, "cont", 4) != 0) {
        printf("> ");
        fgets(cmd, 200, stdin); // Read a line

        if(strncmp(cmd, "registers", 9) == 0 || strncmp(cmd, "regs", 4) == 0) {
            PrintRegs(); // Prints out all of the values of the registers
        } else if(strncmp(cmd, "break ", 6) == 0 || strncmp(cmd, "b ", 2) == 0) {
            strtok(cmd, " "); // The value after the space should be the address in hex
            AddBreakpoint((void *) strtoll(strtok(NULL, " "), 0, 16)); // Adds a breakpoint at that address
        } else if(strncmp(cmd, "mem ", 4) == 0) {
            strtok(cmd, " ");
            char *a = strtok(NULL, " "); // The value after the first space should be the address in hex
            char *b = strtok(NULL, " "); // The value after the second space should be the number of bytes to read in decimal
            ReadMemory(a, atoi(b)); // Read from the given memory address
        } else if(strncmp(cmd, "quit", 4) == 0 || strncmp(cmd, "q", 1) == 0 || strncmp(cmd, "exit", 4) == 0) {
            printf("Debugger will now exit.\n"); // Exit the program
            exit(0);
        } else if(strncmp(cmd, "help", 4) == 0) {
            printf("continue: Continues execution.\n");
            printf("registers: Prints out the values of all of the registers.\n");
            printf("break <addr>: Sets a breakpoint at a given address.\n");
            printf("mem <addr> <bytes>: Reads a given number of bytes from a given memory address.\n");
            printf("quit: Closes the debugger.\n");
        }
    }
    
}

// Called when the debuggee process is being created
void ProcessCreation(DEBUG_EVENT debug_event) {
    // Obtain information about the process's creation
    pInfo = debug_event.u.CreateProcessInfo;

    // Add a breakpoint at the start address
    printf("Setting a breakpoint at the start address...\n");
    AddBreakpoint(pInfo.lpStartAddress);
}

// Called when the debuggee outputs a string
void OutputString(DEBUG_EVENT debug_event) {
    // Obtains information (including a pointer) about the string being printed
    // Note that this pointer is only valid on the debuggee's process, but not on the debugger's process
    // So we'll have to read from the debuggee's process and copy that string's value into a string in our process
    OUTPUT_DEBUG_STRING_INFO DebugString = debug_event.u.DebugString;

    // Create space on the heap to store the string being printed
    char* str = mymalloc(DebugString.nDebugStringLength);

    // Read the string from the debuggee's memory and print it
    ReadProcessMemory(pi.hProcess, DebugString.lpDebugStringData, str, DebugString.nDebugStringLength, NULL);
    printf("Debug String Received: %s\n", str);

    // Free the heap
    free(str);
    str = NULL;
}

void ProcessBreakpoint(DEBUG_EVENT debug_event) {
    if(head != NULL) { // Do nothing if the head of the breakpoint linked list is NULL
        // Get the value of RIP
        CONTEXT lcContext;
        lcContext.ContextFlags = CONTEXT_ALL;
        GetThreadContext(pInfo.hThread, &lcContext); // Obtains the thread context (which contains info about registers)
        lcContext.Rip--; // Move RIP back one byte (RIP would've moved forward as soon as it read INT 3)

        // Find the breakpoint in the linked list, obtain the byte that was originally there and its address, and delete the node from the linked list
        char byte = 0;
        void *addr = NULL;
        char found = 1; // This is set to zero if we did not find the correct byte
        if(head->addr == (void *) lcContext.Rip) { // Triggered if the head is the breakpoint we're looking for
            byte = head->byte; // Save the byte
            addr = head->addr; // Save the address

            // Delete the head
            Breakpoint *del = head;
            head = head->next;
            free(del);
        } else { // Else, loop until we find the correct breakpoint
            Breakpoint *b = head;
            while(b->next != NULL && b->next->addr != (void *) lcContext.Rip) {
                b = b->next;
            }
            if(b->next != NULL) {
                byte = b->next->byte; // Save the byte
                addr = b->next->addr; // Save the address

                // delete the correct node
                Breakpoint *del = b->next;
                b->next = del->next;
                free(del);
            } else { // If this else statement hits, then we did not find the breakpoint in the linked list, and we will just ignore it
                found = 0;
            }
        }
        if(found) {
            // Indicate that we have hit a breakpoint
            dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED; // The debuggee should not handle this exception
            printf("Hit a breakpoint!\n");

            // Apply the change to RIP (which was moved one byte backwards earlier)
            SetThreadContext(pInfo.hThread, &lcContext);

            // Replace the INT 3 instruction with the byte that was originally there
            WriteProcessMemory(pInfo.hProcess, addr, &byte, 1, NULL);
            FlushInstructionCache(pInfo.hProcess, addr, 1);

            // Allow the user to type in commands into the debugger
            ProcessCommands();
        }
    }
}

// Called when the debuggee receives an exception
void ProcessException(DEBUG_EVENT debug_event) {
    // Look at the status for the exception
    int code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
    switch(code) {
        case STATUS_BREAKPOINT: // Called when the exception was caused by a breakpoint
            ProcessBreakpoint(debug_event);
            break;
        default:
            printf("Exception %d (0x%x) received.\n", code, code);
            ProcessCommands(); // Allow the user to type in commands into the debugger
            break;    
    }
}

// Called when the debuggee exits
void ExitDebuggeeProcess(DEBUG_EVENT debug_event) {
    printf("Process exited with code %d (0x%x).\n", debug_event.u.ExitProcess.dwExitCode, debug_event.u.ExitProcess.dwExitCode);
    cont = 0; // Stop the debugger
}


void ProcessDebugEvent(DEBUG_EVENT debug_event) {
    // Reset the continue status (in case it was changed while processing an exception)
    dwContinueStatus = DBG_CONTINUE;

    // Call the correct function depending on what the event code is
    switch(debug_event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: // Called when the debuggee process is first created
            ProcessCreation(debug_event);
            break;
        case OUTPUT_DEBUG_STRING_EVENT: // Called when a string is sent to the debugger for display
            OutputString(debug_event);
            break;
        case EXCEPTION_DEBUG_EVENT: // Called whenever any exception occurs in the process being debugged
            ProcessException(debug_event);
            break;
        case EXIT_PROCESS_DEBUG_EVENT: // Called when the debuggee process exits
            ExitDebuggeeProcess(debug_event);
            break;
    }
}

int main(int argc, char** argv) {
    // Initialize some variables
    STARTUPINFO si; // Contains startup information about the debugged process
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create the process to debug
    CreateProcessA(argv[1], NULL, NULL, NULL, 0, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);

    // Process debugging events
    DEBUG_EVENT debug_event = {0};
    while(cont) {
        if(!WaitForDebugEvent(&debug_event, INFINITE)) {
            break; // Break the loop if the function fails
        }
        ProcessDebugEvent(debug_event); // User-defined function that will process the event
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus); // Continue execution
    }

    // Exit the debugger
    printf("Debugger will now exit.\n");
    return 0;
}
