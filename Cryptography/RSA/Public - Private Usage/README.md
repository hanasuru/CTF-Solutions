## Problem
Penyisihan Keamanan Jaringan dan Sistem Informasi Gemastik 11

## Deskripsi
Diberikan 4 buah file encrypted dengan nama flag0.enc sampai flag3.enc dan 1 buah file public key dengan format PEM.
Diasumsikan 4 file tersebut dienkripsi dengan key yang sama.
Dengan menggunakan tool dari [Ganapati/RsaCtfTool/](https://github.com/Ganapati/RsaCtfTool/), didapatkan private key-nya

    python RsaCtfTool.py --publickey public_key.pem --private > private_key.pem

Setelah didapatkan private key-nya, encrypted dapat di-decrypt dengan command

    openssl rsautl -decrypt -in flag0.enc -inkey private.pem
    openssl rsautl -decrypt -in flag1.enc -inkey private.pem
    openssl rsautl -decrypt -in flag2.enc -inkey private.pem
    openssl rsautl -decrypt -in flag3.enc -inkey private.pem

Flag : GEMASTIK{Gem4571kITS}


