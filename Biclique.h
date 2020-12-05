#ifndef BICLIQUE_H
#define BICLIQUE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>


#define d 8.0 //Bicliqueの次元　8が最大で仕様通り
#define SSize 16 //State S の配列のサイズ
#define CSize 16 //Ciphertext C の配列のサイズ
#define PSize 16 //Plaintext P の配列のサイズ
#define KeySize 16 //Keyの配列のサイズ
#define Number_of_i (int)pow(2.0,d) //C,Pの個数　256が最大
#define Number_of_j (int)pow(2.0,d) //Sの個数　256が最大
#define Number_of_Key (int)pow(2.0,(2*d)) //Keyの個数　65536が最大
#define Number_of_struct (int)pow(2.0,(2*d)) //構造体の個数　65536が最大
#define bytemin 0 //1byteの最小値（乱数生成に使用）
#define bytemax 255 //1byteの最大値（乱数生成に使用）
#define Biclique_Start 8 //Biclique攻撃のスタートラウンド
#define Biclique_End 10 //Biclique攻撃の終わりのラウンド
#define Biclique_challenge_time 10 //Biclique攻撃の回数

typedef struct state_forward{
    u_int8_t state0[SSize];
    u_int8_t state1[SSize];
    u_int8_t state2[SSize];
    u_int8_t state3[SSize];
    u_int8_t state4[SSize];
    u_int8_t state5[SSize];
    u_int8_t aftsb1[SSize];
} SF;

typedef struct state_backward{
    u_int8_t state15[SSize];
    u_int8_t state14[SSize];
    u_int8_t state13[SSize];
    u_int8_t state12[SSize];
    u_int8_t state11[SSize];
    u_int8_t state10[SSize];
    u_int8_t state9[SSize];
    u_int8_t state8[SSize];
    u_int8_t state7[SSize];
    u_int8_t state6[SSize];
    u_int8_t state5[SSize];
} SB;


typedef struct Biclique{
    u_int8_t S[SSize];
    u_int8_t C[CSize];
    u_int8_t P[PSize];
    u_int8_t BicliqueKey[KeySize];
    u_int8_t Delta_i[CSize];
    u_int8_t Nabra_j[SSize];
    u_int8_t subkey[KeySize*8];
    u_int8_t candKey[KeySize];
    u_int8_t cmp_P[PSize];
    u_int8_t Vi;
    u_int8_t Vj;
    SF f_state;
    SB b_state;
    u_int8_t cmpflag;
} BICL;


void createBiclique(BICL *Biclique,int seed);
void KeyCreate(u_int8_t *Key,int seed);
void conversion_C2P(BICL *Biclique,u_int8_t *secretKey);
void precompute_P2v(BICL *Biclique);
void precompute_S2v(BICL *Biclique);
void recompute(BICL *Biclique);
void fcompute(u_int8_t *C,u_int8_t *P,u_int8_t *key);


#endif