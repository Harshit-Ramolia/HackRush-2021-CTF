# HackRush 2021 CTF

We participated in this 3 day long capture the flag (CTF) competition hosted by HackRush at IITGN and secored the 1st position. We had no previous experience of solving CTF challenges and had participated with the hope to know something about hacking. It is needless to say that this competition provided us the experience we needed. 

We enjoyed solving the questions, although we had to spent lots of time going through the resources and understanding the questions. But after spending time and effort, when you come across a hex byte or a string that starts as "Hack", the feeling of exhilaration is extremely rewarding.

<br>


Problem | Category | Points | Flag
--------|:----------:| :-----: |:-----:
|||<br>
cliff | Binary Exploitation | 300 | HackRushCTF{N0w_Y0u_kn0w_ab0ut_form4t_5tr1ng5}
simple_login | Binary Exploitation | 500| -
echo_back | Binary Exploitation | 1000|-
real_hack | Binary Exploitation | 1500|-
|||<br>
simple_check | Reverse Engineering | 200 |HackRushCTF{x86_f1r5t_t1me?}
so_slooow | Reverse Engineering | 500 |-
mixed_up | Reverse Engineering | 1000 | HackRushCTF{Gh1dr4_1s_Tru!y_4w3s0m3}
|||<br>
Ancient | Cryptography | 50 | HackRushCTF{asoka​}
prime magic 1 | Cryptography | 100 | HackRushCTF{RSA_1s_c00l}
prime magic 2 | Cryptography | 300 | HackRushCTF{10_1s_b3tt3r_th4n_2?}
Double the trouble | Cryptography | 800 | HackRushCTF{7w1c3_1s_n0t_b3tt3r}


<br>
<br>


## Binary Exploitation

1. ### **cliff (300 pts):**
    
    **Challenge**
    
    Have you heard about garbage in, garbage out?
    
    Connect to the actual challenge using: 

    nc 3.142.26.175 12345

    The [C code]() and [compiled binary]() are given.
    <br>
    
    **Solution**

    After seeing the c code, we found out that, there is a `flag` variable in main function. The main function is opening a txt file and reading it and storing its value in `flag`. There is no way we could get the value of flag without the file, hence we can only get the flag variable by some exploitation on the sever end.

    We used format string vulnerability to obtain the hex values of the flag. As mentioned in [this article](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/) `printf` can leak information from the stack if we input `%llx`. This gives the long long hex value from the stack. Using this information, we gave the input as a long string - <br>
    
    ```%llx %llx %llx %llx %llx %llx %llx %llx %llx %llx``` <br>
    
    as input to the given server IP and port (3.142.26.175, 12345). 
    
    <br>  

    We then ran the above input multiple times and noticed that only some values repeated whereas other values changed on each execution. This meant that the values that were changing must be garbage values whereas the values that did not change must represent some actual information. We observed that value starting from `%10$llx` remained the same. We then converted the output hex to Ascii and found “hsuRkcaH” as the Ascii value. This result motivated us and we felt that we were on the right track. We then fetched values uptill %15$llx after which the values again changed on different iterations. On decoding the hex values obtained from %10$llx to %15$llx, and reversing each string, we got the desired flag.
