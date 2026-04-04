/* Brrq contract linker script for brrq-vm.
 * Code is loaded at address 0 and execution starts at PC=0.
 * .text is placed first so _start is at (or near) address 0.
 */
ENTRY(_start)

SECTIONS {
    . = 0;

    .text : {
        *(.text._start)
        *(.text .text.*)
    }

    . = ALIGN(4);
    .rodata : {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4);
    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
    }

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.riscv.attributes)
    }
}
