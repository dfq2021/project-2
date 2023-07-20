#include<iostream>
#include<bitset>
#include<sstream>
#include<fstream>
#include"sm3.h"
using namespace std;
#pragma warning(disable:4996)

int sm3_rho_collide() {
    cout << "待碰撞信息为：";
    char plaintext[] = "abc";
    cout << plaintext << endl;
    int hash_val[8];
    int hash_val2[8];
    int hash_val3[8];
    sm3(plaintext, hash_val);
    cout << "待碰撞信息的hash为：" << endl;
    dump_buf((char*)hash_val, 32);

    sm3(plaintext, hash_val2);
    while (1) {
        memcpy(hash_val3, hash_val2, 32);
        sm3((char*)hash_val2, hash_val2);
        if (!memcmp(hash_val, hash_val2, 2)) {
            cout << "碰撞到的信息为：" << endl;
            dump_buf((char*)hash_val3, 32);
            cout << "碰撞到的信息的Hash为：" << endl;
            dump_buf((char*)hash_val2, 32);
            break;
        }
    }
    cout << "可以碰撞" << 2 * 8 << "bit的信息" << endl;
    return 0;
}



int main() {
    clock_t startTime = clock();
    sm3_rho_collide();
    clock_t endTime = clock();
    cout << "整个程序用时：" << double(endTime - startTime) / CLOCKS_PER_SEC << "s" << endl;
    system("pause");
}