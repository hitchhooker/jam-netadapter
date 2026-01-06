/* polkavm linker script for jam services */

ENTRY(refine)

SECTIONS
{
    . = 0x10000;

    .text : {
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
    }

    /* polkavm dispatch table */
    .polkavm_exports : {
        *(.polkavm_exports)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
