# Emulated Cortex-M4 measurements

`firmware/` holds the sender-side code of every compared scheme (`bench.c`), a minimal C runtime
(`fwlib.c`, `inc/`), the wolfCrypt configuration (`user_settings.h`) and the linker script.
`host/run.c` loads the firmware into the Unicorn engine (ARM, Cortex-M4 model), calls each
function and counts executed instructions and cycles (Cortex-M4 TRM timing, zero wait states).

Build (Linux, clang 18 with the ARM backend, ld.lld, wolfSSL v5.7.6-stable, Unicorn 2.1.3,
compiler-rt builtins `aeabi_uldivmod`, `aeabi_memset`, `udivmoddi4`):

```
CF=$(cat firmware/cflags.txt)          # adjust -I to your wolfSSL checkout
for f in aes sha256 sha512 hmac hash random rsa ecc sp_int sp_c32 wolfmath curve25519 ed25519 \
         fe_operations ge_operations chacha poly1305 chacha20_poly1305 memory logging error asn \
         coding wc_port wc_encrypt signature kdf; do clang $CF -c $WOLFSSL/wolfcrypt/src/$f.c -o obj/$f.o; done
clang $CF -c firmware/bench.c -o obj/bench.o; clang $CF -c firmware/fwlib.c -o obj/fwlib.o
ld.lld -T firmware/link.ld --gc-sections -u <each op_/pkt_/sess_ function> obj/*.o -o fw.elf
llvm-objcopy -O binary fw.elf fw.bin; llvm-nm fw.elf | awk '{print $3, $1}' > syms.txt
gcc -O2 -I$UNICORN/include host/run.c -o run $UNICORN/build/libunicorn.a -lpthread -lm
./run fw.bin syms.txt firmware/plan-full2.txt mcu-emulated.csv
```

`results/mcu-emulated-sp-math.csv` uses wolfCrypt's specialised C code for RSA and P-256
(`WOLFSSL_HAVE_SP_RSA`, `WOLFSSL_HAVE_SP_ECC`); `results/mcu-emulated-generic-math.csv` uses the
generic code. The paper reports the faster of the two for each baseline.
`results/mcu-window.csv` is the window packet with the 25-byte header.
