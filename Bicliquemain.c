#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "AES.h"
#include "Biclique.h"



int main(int argc,char *argv[]){
    int i,j;
    int k,x;
    int flag = 0;
    int count = 0;
    int seed;
    
    u_int8_t secretKey[KeySize] = {0xf7,0x60,0xd5,0xa,0x65,0xab,0x4d,0x9d,0x9e,0x66,0xb,0x8c,0x81,0x64,0xe7,0x95};
    BICL *Biclique;

    Biclique = (BICL *)malloc(sizeof(BICL) * Number_of_struct);
    
    //KeyCreate(secretKey,seed);

    seed = atoi(argv[1]);

    for(x = 0;x < Biclique_challenge_time;x++){
        printf("---------------------------------Start Biclique-----------------------------------\n");
        for(i = 0;i < Number_of_struct;i++){
            Biclique[i] = (BICL){0};
        }

        createBiclique(Biclique,seed+x);
        conversion_C2P(Biclique,secretKey);
        precompute_P2v(Biclique);
        precompute_S2v(Biclique);
        recompute(Biclique);
    //////////////////////結果の出力////////////////////////////
        printf("i = %d j = %d Number_of_Key = %d seed = %d\n",Number_of_i,Number_of_j,Number_of_Key,seed+x);


        printf("---------------------------------End Biclique-----------------------------------\n");

        printf("----------Secret key-------------\n");

        for(k = 0;k < KeySize -1;k++){
            printf("%x,",secretKey[k]);
        }
        printf("%x\n",secretKey[k]);

        

        /*printf("----------Cipher text C----------\n");
        for(i = 0;i < Number_of_struct;i++){
            printf("C[%d] is :",i);
            for(k = 0;k < CSize - 1;k++){
                printf("%x,",Biclique[i].C[k]);
            }
            printf("%x\n",Biclique[i].C[k]);
        }

        printf("----------Plain text P-----------\n");
        for(i = 0;i < Number_of_struct;i++){
            printf("P[%d] is :",i);
            for(k = 0;k < PSize - 1;k++){
                printf("%x,",Biclique[i].P[k]);
            }
            printf("%x\n",Biclique[i].P[k]);
        }

        printf("----------Middle data S----------\n");

        for(j = 0;j < Number_of_struct;j++){
            printf("S[%d] is :",j);
            for(k = 0;k < SSize-1;k++){
                printf("%x,",Biclique[j].S[k]);
            }
            printf("%x\n",Biclique[j].S[k]);
        }

        /*printf("----------Delta_i-----------\n");
        for(i = 0;i < Number_of_struct;i++){
            printf("delta_%d is :",i);
            for(k = 0;k < CSize - 1;k++){
                printf("%x,",Biclique[i].Delta_i[k]);
            }
            printf("%x\n",Biclique[i].Delta_i[k]);
        }

        printf("----------Nabra_j-----------\n");
        for(i = 0;i < Number_of_struct;i++){
            printf("Nabra_%d is :",i);
            for(k = 0;k < SSize - 1;k++){
                printf("%x,",Biclique[i].Nabra_j[k]);
            }
            printf("%x\n",Biclique[i].Nabra_j[k]);
        }

        printf("----------Key[i][j]-----------\n");
        for(j = 0;j < Number_of_j;j++){
            for(i = 0;i < Number_of_i;i++){
                printf("K[%d][%d] is :",i,j);
                for(k = 0;k < KeySize - 1;k++){
                    printf("%x,",Biclique[j*Number_of_j+i].BicliqueKey[k]);
                }
                printf("%x\n",Biclique[j*Number_of_j+i].BicliqueKey[k]);
            }
        }

        printf("----------Round 0 Key[i][j]-----------\n");
        for(j = 0;j < Number_of_j;j++){
            for(i = 0;i < Number_of_i;i++){
                printf("K[%d][%d] is :",i,j);
                for(k = 0;k < KeySize - 1;k++){
                    printf("%x,",Biclique[j*Number_of_j+i].subkey[112+k]);
                }
                printf("%x\n",Biclique[j*Number_of_j+i].subkey[112+k]);
            }
        }*/
        printf("----------Start Compare-----------\n");

        for(i = 0;i < Number_of_struct;i++){
            if(Biclique[i].Vi == Biclique[i].Vj){
                printf("Perhaps there's a secret key in here ");
                printf("K[%d][%d]\n",i%Number_of_i,i/Number_of_j);
                for(k = 0;k < KeySize - 1;k++){
                    printf("%x,",Biclique[i].subkey[112+k]);
                }
                printf("%x\n",Biclique[i].subkey[112+k]);
                printf("Vi is : %x\t",Biclique[i].Vi);
                printf("Vj is : %x\n",Biclique[i].Vj);
                printf("--------------------------------------------------------------------\n");
                count++;
                Biclique[i].cmpflag = 1;
            } else{

            }
            //printf("Vi is : %x\t",Biclique[i].Vi);
            //printf("Vj is : %x\n",Biclique[i].Vj);
        }

        for(i = 0;i < Number_of_struct;i++){
            if(Biclique[i].cmpflag){
                fcompute(Biclique[i].C,Biclique[i].cmp_P,Biclique[i].candKey);
                if(!memcmp(Biclique[i].P,Biclique[i].cmp_P,PSize)){
                    printf("secret key is:");
                    printf("K[%d][%d]\n",i%Number_of_i,i/Number_of_j);
                    for(k = 0;k < KeySize - 1;k++){
                        printf("%x,",Biclique[i].candKey[k]);
                    }
                    printf("%x\n",Biclique[i].candKey[k]);
                    flag = 1;
                }
            }
        }

        if(!flag){
            printf("There's no secret key in here\n");
        } else{
            exit(0);
        }
        printf("count is %d\n",count);
        count = 0;

    }
    free(Biclique);
}
        

