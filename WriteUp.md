# HackRush 2021 CTF

We participated in this 3 day long capture the flag (CTF) competition hosted by [HackRush](http://3.142.26.175/) at IITGN and secured the 1st position. We had no previous experience of solving CTF challenges and had participated with the hope to know something about hacking. It is needless to say that this competition provided us the experience we needed. 

We enjoyed solving the questions, although we had to spent lots of time going through the resources and understanding the questions. But after spending time and effort, when you come across a hex byte or a string that starts as "Hack", the feeling of exhilaration is extremely rewarding.

<br>


Problem | Category | Points | Flag
--------|:----------:| :-----: |:-----:
|||<br>
[cliff](https://github.com/Harshit-Ramolia/HackRush-2021-CTF/blob/main/WriteUp.md#cliff-300-pts) | Binary Exploitation | 300 | HackRushCTF{N0w_Y0u_kn0w_ab0ut_form4t_5tr1ng5}
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


## **Binary Exploitation**

1. ### **cliff (300 pts):**
    
    **Challenge**
    
    Have you heard about garbage in, garbage out?
    Connect to the actual challenge using: 

    nc 3.142.26.175 12345

    The [C code](https://github.com/Harshit-Ramolia/HackRush-2021-CTF/blob/main/problem-files/binary-exploitation/cliff.c) and [compiled binary](https://github.com/Harshit-Ramolia/HackRush-2021-CTF/blob/main/problem-files/binary-exploitation/cliff) are given.
    
    <br>
    
    **Solution**

    After seeing the c code, we found out that, there is a `flag` variable in main function. The main function is opening a txt file and reading it and storing its value in `flag`. There is no way we could get the value of flag without the file, hence we can only get the flag variable by some exploitation on the sever end.

    We used format string vulnerability to obtain the hex values of the flag. As mentioned in [this article](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/) `printf` can leak information from the stack if we input `%llx`. This gives the long long hex value from the stack. Using this information, we gave the input as a long string - <br>
    
    ```%llx %llx %llx %llx %llx %llx %llx %llx %llx %llx``` <br>
    
    to the given server IP and port (3.142.26.175, 12345). 

    <br>

    We then ran the above input multiple times and noticed that only some values repeated whereas other values changed on each execution. This meant that the values that were changing must be garbage values whereas the values that did not change must represent some actual information. We observed that value starting from `%10$llx` remained the same. Converting the output hex of `%10$llx` to ASCII we got “hsuRkcaH” as the ASCII value. This result motivated us and we felt that we were on the right track. We then fetched values uptill `%15$llx` after which the values again changed on different iterations. On decoding the hex values obtained from `%10$llx` to `%15$llx`, and reversing each string, we got the desired flag.

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{N0w_Y0u_kn0w_ab0ut_form4t_5tr1ng5}**

<br>

## **Reverse Engineering**

1. ### **simple_check (200 pts)**

    **Challenge**

    Check this out, you can test if your flag is valid or not!<br>
    The [C code](https://github.com/Harshit-Ramolia/HackRush-2021-CTF/blob/main/problem-files/reverse-engineering/simple_check.c) and [compiled binary](https://github.com/Harshit-Ramolia/HackRush-2021-CTF/blob/main/problem-files/reverse-engineering/simple_check) are given.

    **Solution**

    // Add solution

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{x86_f1r5t_t1m3?}**

<br>

2. ### **mixed_up (1000 pts)**

    **Challenge**<br>
    What a terrible mess<br>
    Here is the [compiled binary](https://github.com/Harshit-Ramolia/HackRush-2021-CTF/blob/main/problem-files/reverse-engineering/mixed_up).

    **Solution**<br>
    First we tried to use the `strings` command to list out all the strings present in the binary file to see if the flag was stored as plaintext. This was not the case. So, we tried to analyse the binary file using tools like gdb and radare2.<br> 
    Using radare2, we made some important conclusion. First off, the `main` function called a `check_flag` function. In `check_flag`, there seemed to be some sort of while loop that was run until the counter was incremented from 0 to 36. This could mean that the flag has a length of 36 which was confirmed later on. We made a few more deductions, but the assembly code was very complex to understand. After going through some online resources and [this](https://www.youtube.com/watch?v=RCgEIBfnTEI) video, we came across a wonderful tool called Ghidra.<br> 
    Ghidra is an awesome tool that decompiled the binary file to a C file. Now, analysing the code was relatively easy. We found that `check_flag` was first encrypted using the `mixup` function and then it was checked against an array called `flag`. The `flag` array contained hex values. On further investigation, we found that the input was reversed and then compared with `flag`, meaning that we needed to reverse `flag` in order to obtain the correct value. Also, the input was compared only with the corresponding multiples of 4 (0, 4, 8, and so on) in the `flag` array. Thus, we had to decrypt the values present at multiples of 4 starting from index 0 and ending at index 140 ((36-1) * 4). On converting to ASCII and reversing, we captured the flag.

    // add code for decrypting<br>
    PS: The flag truly lives up to its name.

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{Gh1dr4_1s_Tru!y_4w3s0m3}**

<br>

## **Cryptography**

1. ### **Ancient (50 pts)**

    **Challenge**<br>
    I found some wierd text, Can you find out what this means?

    **Solution**<br>
    //add soln<br>
    After searching few letters it was easy to know that symbols belongs to brahmin script

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{asoka​}**

    <br>

2. ### **prime magic 1 (100 pts)**

    **Challenge**<br>
    This should be simple.<br>
    The correct output is given at the end of the script in comments<br>
    [Here](https://github.com/Harshit-Ramolia/HackRush-2021-CTF/blob/main/problem-files/cryptography/prime_magic_1.py) is the attached python file.

    **Solution**<br>
    After reading resource about RSA from [this](https://ctf101.org/cryptography/what-is-rsa/) website, we concluded that we had to break the `big_num` into its prime factors.<br>
    We obtained the prime factors using [this](https://www.alpertron.com.ar/ECM.HTM) tool. 

    // complete soln, add code

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{RSA_1s_c00l}**

    <br>

3. ### **prime magic 2 (300 pts)**

    **Challenge**<br>
    The same challenge again?<br>
    [Here](https://github.com/Harshit-Ramolia/HackRush-2021-CTF/blob/main/problem-files/cryptography/prime_magic_2.py) is the attached python file.

    **Solution**<br>
    

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{10_1s_b3tt3r_th4n_2?}**

    <br>

4. ### **Double the trouble (800 pts)**

    **Challenge**<br>
    Wow, double the security! No one can know the flag now!<br>
    [Here](https://github.com/Harshit-Ramolia/HackRush-2021-CTF/blob/main/problem-files/cryptography/double_the_trouble.py) is the attached python file.

    **Solution**<br>
    We first proceeded by taking a for loop that was nested 6 times to find the last three bytes in both the keys.

    **FLAG: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HackRushCTF{7w1c3_1s_n0t_b3tt3r}**

    <br>
