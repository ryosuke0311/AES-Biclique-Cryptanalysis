#ifndef AES_H
#define AES_H

#include <stdlib.h>
#include "Biclique.h"
#define Nk 4
#define Nr 10
#define Nb 4


void subBytes(u_int8_t *state);
void RsubBytes(u_int8_t *state,u_int8_t *Rtable,int size);
static void inv_sub_bytes(u_int8_t* state /*4*Nb*/);
static void Rinv_sub_bytes(u_int8_t* state,u_int8_t *Rtable,int size);
void shiftRows(u_int8_t *state);
static void inv_shift_rows(u_int8_t* state);
void Mixcolumns(u_int8_t *state);
static void inv_mix_columns(u_int8_t* state /*4*Nb*/);
static u_int8_t gmult(u_int8_t a, u_int8_t b);
void AddRoundkey(u_int8_t *state,u_int8_t rcount);
void BAddRoundkey(u_int8_t *state,u_int8_t rcount);
void KeyExpantion(u_int8_t *key);
void invKeyExpantion(u_int8_t *key);
void RotWord(u_int8_t *temp);
void SubWord(u_int8_t *temp);
void xor_Rcon(u_int8_t *temp,u_int8_t i);
void KeyExpantion2(u_int8_t *key,u_int8_t *Dkey); //Fig4の実現のためのKeySchedule
void KeyExpantion3(u_int8_t *key,u_int8_t *frkey); //Fig6実現のためのKeySchedule
void KeyExpantion4(u_int8_t *key,u_int8_t *brkey); //Fig5実現のためのKeySchedule
void KeyRecompute(u_int8_t *zsubkey,u_int8_t *isubkey,u_int8_t *jsubkey,u_int8_t *recompsubkey);
void Enc(u_int8_t *in,u_int8_t *out,int start,int end);
void BEnc(u_int8_t *in,u_int8_t *out,int start,int end); //Fig4実現のためのEnc
void PEnc(u_int8_t *in,SF *f_state,u_int8_t *k); //Fig6の事前計算のためのEnc
void RecomputeF(u_int8_t *in,SF *f_state,SF *recomp_state,u_int8_t *k); //Fig6の再計算のためのEnc
void Dec(u_int8_t *in,u_int8_t *out,int start,int end);
void Binv_f(u_int8_t *in,u_int8_t *out,int start,int end); //Fig4実現のためのinv_f
void Pinv_f(u_int8_t *in,SB *b_state,u_int8_t *k); //Fig5の事前計算のためのinv_f
void RecomputeB(u_int8_t *in,SB *b_state,SB *recomp_state,u_int8_t *k); //Fig5の再計算のためのinv_f


#endif