ENTRY(setup)
MEMORY { RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 4M }
SECTIONS {
  .text : { *(.text*) *(.rodata*) } > RAM
  .ARM.exidx : { *(.ARM.exidx*) } > RAM
  .data : { *(.data*) } > RAM
  .bss (NOLOAD) : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; } > RAM
  __end = .;
}
