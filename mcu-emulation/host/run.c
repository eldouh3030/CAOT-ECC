/* Host harness: runs firmware functions on an emulated ARM Cortex-M4 (Unicorn)
   and reports executed instructions and estimated cycles per call.

   Cycle model (Cortex-M4 TRM, Table 3-1, zero-wait-state memory):
     data processing, MUL/MLA, UMULL/SMULL/UMLAL/SMLAL ... 1
     SDIV/UDIV ........................................... 7 (2-12)
     LDR (single) ........................................ 2, or 1 when it directly
                                                           follows a load/store (pipelined)
     STR (single) ........................................ 1
     LDRD/STRD ........................................... 3
     LDM/STM/PUSH/POP .................................... 1 + number of registers
     taken branch / write to PC .......................... +2 (pipeline refill, 1+P with P=2)
   usage: run <fw.bin> <syms.txt> <plan.txt> <out.csv>
     plan.txt lines: <function> <payload_len> <repetitions>                     */
#include <unicorn/unicorn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BASE    0x20000000u
#define RAMSZ   (4u << 20)
#define STOP    0x30000000u
#define STACK   (BASE + RAMSZ - 16)

static uint8_t* img; static size_t imgsz;
static uint64_t n_insn, n_cyc;
static int prev_ls, prev_branch; static uint64_t expect_next;
static int counting;

static int popcnt(uint32_t x) { return __builtin_popcount(x); }

static void hook(uc_engine* uc, uint64_t addr, uint32_t size, void* ud) {
    (void)uc; (void)ud;
    if (!counting) return;
    if (prev_branch && addr != expect_next) n_cyc += 2;     /* branch taken: refill */
    uint32_t off = (uint32_t)(addr - BASE);
    uint16_t h1 = img[off] | (img[off + 1] << 8);
    int cyc = 1, ls = 0, br = 0;
    if (size == 2) {
        if ((h1 & 0xF800) == 0x4800) { cyc = prev_ls ? 1 : 2; ls = 1; }                  /* LDR literal */
        else if ((h1 & 0xF000) == 0x5000) { int op = (h1 >> 9) & 7; ls = 1; cyc = op >= 3 ? (prev_ls ? 1 : 2) : 1; }
        else if ((h1 & 0xE000) == 0x6000 || (h1 & 0xF000) == 0x8000 || (h1 & 0xF000) == 0x9000) {
            ls = 1; cyc = (h1 & 0x0800) ? (prev_ls ? 1 : 2) : 1; }
        else if ((h1 & 0xFE00) == 0xB400) cyc = 1 + popcnt(h1 & 0xFF) + ((h1 >> 8) & 1);  /* PUSH */
        else if ((h1 & 0xFE00) == 0xBC00) { cyc = 1 + popcnt(h1 & 0xFF) + ((h1 >> 8) & 1); if (h1 & 0x100) br = 1; } /* POP */
        else if ((h1 & 0xF000) == 0xC000) cyc = 1 + popcnt(h1 & 0xFF);                    /* LDM/STM */
        else if ((h1 & 0xF000) == 0xD000 && (h1 & 0x0F00) < 0x0E00) br = 1;               /* B<cond> */
        else if ((h1 & 0xF800) == 0xE000) br = 1;                                         /* B */
        else if ((h1 & 0xFF00) == 0x4700) br = 1;                                         /* BX/BLX */
        else if ((h1 & 0xF500) == 0xB100) br = 1;                                         /* CBZ/CBNZ */
        else if ((h1 & 0xFF87) == 0x4687) br = 1;                                         /* MOV pc,Rm */
    } else {
        uint16_t h2 = img[off + 2] | (img[off + 3] << 8);
        if ((h1 & 0xF800) == 0xF000 && (h2 & 0x8000)) {                                      /* B/BL/B<cond>, misc */
            if ((h2 & 0xD000) == 0x8000) br = (((h1 >> 6) & 7) != 7); else br = 1; }
        else if ((h1 & 0xFE40) == 0xE800 || (h1 & 0xFE40) == 0xE900) {                    /* LDM/STM/PUSH/POP */
            cyc = 1 + popcnt(h2); if ((h1 & 0x0010) && (h2 & 0x8000)) br = 1; }
        else if ((h1 & 0xFE40) == 0xE840) {                                                /* LDRD/STRD, TBB/TBH, LDREX */
            if ((h1 & 0xFFF0) == 0xE8D0 && (h2 & 0xFFE0) == 0xF000) { cyc = 2; br = 1; }
            else { cyc = 3; ls = 1; } }
        else if ((h1 & 0xFE00) == 0xF800) {                                                /* single load/store */
            ls = 1;
            if (h1 & 0x0010) { cyc = prev_ls ? 1 : 2; if (((h2 >> 12) & 0xF) == 0xF && (h1 & 0x0060) == 0x0040) br = 1; }
            else cyc = 1; }
        else if ((h1 & 0xFFF0) == 0xFB90 || (h1 & 0xFFF0) == 0xFBB0) cyc = 7;            /* SDIV/UDIV */
        else if ((h1 & 0xEE00) == 0xEC00) { if ((h1 & 0xFE00) == 0xED00 && (h1 & 0x10)) cyc = 2; } /* VFP */
    }
    if (br) { prev_branch = 1; expect_next = addr + size; } else prev_branch = 0;
    prev_ls = ls;
    n_insn++; n_cyc += cyc;
}

static uint32_t sym(const char* file, const char* name) {
    FILE* f = fopen(file, "r"); char n[128]; unsigned a;
    while (fscanf(f, "%127s %x", n, &a) == 2) if (!strcmp(n, name)) { fclose(f); return a; }
    fclose(f); fprintf(stderr, "symbol %s not found\n", name); exit(1);
}

static int call(uc_engine* uc, uint32_t fn) {
    uint32_t sp = STACK, lr = STOP | 1;
    uc_reg_write(uc, UC_ARM_REG_SP, &sp);
    uc_reg_write(uc, UC_ARM_REG_LR, &lr);
    prev_ls = prev_branch = 0;
    uc_err e = uc_emu_start(uc, fn | 1, STOP, 0, 0);
    if (e) { uint32_t pc; uc_reg_read(uc, UC_ARM_REG_PC, &pc); fprintf(stderr, "emu error %s at pc=%08x\n", uc_strerror(e), pc); return -1; }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 5) { fprintf(stderr, "usage\n"); return 1; }
    FILE* f = fopen(argv[1], "rb"); fseek(f, 0, SEEK_END); imgsz = ftell(f); rewind(f);
    img = calloc(1, RAMSZ); fread(img, 1, imgsz, f); fclose(f);
    uc_engine* uc;
    if (uc_open(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, &uc)) { fprintf(stderr, "uc_open\n"); return 1; }
    uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_M4);
    uc_mem_map(uc, BASE, RAMSZ, UC_PROT_ALL);
    uc_mem_map(uc, STOP, 0x1000, UC_PROT_ALL);
    uc_mem_write(uc, BASE, img, RAMSZ);
    uc_hook hh; uc_hook_add(uc, &hh, UC_HOOK_CODE, hook, NULL, 1, 0);
    const char* syms = argv[2];
    uint32_t a_len = sym(syms, "g_len"), a_st = sym(syms, "g_status"), a_reset = sym(syms, "heap_reset");

    counting = 0;
    if (call(uc, sym(syms, "setup"))) return 1;
    int32_t st; uc_mem_read(uc, a_st, &st, 4);
    if (st) { fprintf(stderr, "setup failed: %d\n", st); return 1; }
    fprintf(stderr, "setup ok\n");

    FILE* plan = fopen(argv[3], "r"); FILE* out = fopen(argv[4], "w");
    fprintf(out, "function,payload_bytes,reps,instructions,cycles,ms_at_120MHz,ms_at_80MHz\n");
    char fn[128]; unsigned len, reps;
    while (fscanf(plan, "%127s %u %u", fn, &len, &reps) == 3) {
        uint32_t a = sym(syms, fn);
        uc_mem_write(uc, a_len, &len, 4);
        counting = 0; call(uc, a_reset); call(uc, a);              /* warm-up (static init) */
        uint64_t ti = 0, tc = 0;
        for (unsigned r = 0; r < reps; ++r) {
            counting = 0; call(uc, a_reset);
            n_insn = n_cyc = 0; counting = 1;
            if (call(uc, a)) return 1;
            counting = 0;
            uc_mem_read(uc, a_st, &st, 4);
            if (st) { fprintf(stderr, "%s failed: %d\n", fn, st); return 1; }
            ti += n_insn; tc += n_cyc;
        }
        double ci = (double)ti / reps, cc = (double)tc / reps;
        fprintf(out, "%s,%u,%u,%.0f,%.0f,%.4f,%.4f\n", fn, len, reps, ci, cc, cc / 120e3, cc / 80e3);
        fprintf(stderr, "%-24s %5u B  insn %12.0f  cyc %12.0f  %9.3f ms @120MHz\n", fn, len, ci, cc, cc / 120e3);
        fflush(out);
    }
    fclose(out); uc_close(uc);
    return 0;
}
