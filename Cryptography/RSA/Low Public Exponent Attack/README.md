## Problem
PicoCTF 2018 <br/>
Safe RSA <br/>

## Deskripsi
Diberikan sebuah file ciphertext yang berisi variabel - variabel pada RSA, yaitu <br/>
    N: 374159235470172130988938196520880526947952521620932362050308663243595788308583992120881359365258949723819911758198013202644666489247987314025169670926273213367237020188587742716017314320191350666762541039238241984934473188656610615918474673963331992408750047451253205158436452814354564283003696666945950908549197175404580533132142111356931324330631843602412540295482841975783884766801266552337129105407869020730226041538750535628619717708838029286366761470986056335230171148734027536820544543251801093230809186222940806718221638845816521738601843083746103374974120575519418797642878012234163709518203946599836959811
    e: 3
    C: 2205316413931134031046440767620541984801091216351222789180593875373829950860542792110364325728088504479780803714561464250589795961097670884274813261496112882580892020487261058118157619586156815531561455215290361274334977137261636930849125

Diketahui *vulnerability* ada pada e-nya yang kecil.<br/>
Setelah membaca referensi dari [Stackoverflow](https://stackoverflow.com/questions/356090/how-to-compute-the-nth-root-of-a-very-big-integer), dibuatlah *script* solver.py yang berisi<br/>

    import gmpy
    from Crypto.Util.number import *
    i0 = 2205316413931134031046440767620541984801091216351222789180593875373829950860542792110364325728088504479780803714561464250589795961097670884274813261496112882580892020487261058118157619586156815531561455215290361274334977137261636930849125
    m0 = gmpy.mpz(i0)
    print long_to_bytes((long( m0.root(3)[0])))

Ketika dijalankan, didapatkan flag-nya<br/>

    python solver.py
    picoCTF{e_w4y_t00_sm411_9f5d2464}

Flag : picoCTF{e_w4y_t00_sm411_9f5d2464}