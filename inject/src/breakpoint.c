/* Use C to access inline asm */
void breakpoint() {
    asm("int3");
}