#include <stdio.h>

#include "tables.h"
#include "rijndael.h"

int main(void) {
	xword32 key[8] = { 0x00000000, 0, 0, 0, 0, 0, 0, 0};
	xword32 pln[8] = { 0, 0, 0, 0, 0, 0, 0, 0};
	xword32 cph[8] = { 0xE62ABCE0, 0x69837B65, 0x309BE4ED, 0xA2C0E149,
                       0xFE56C07B, 0x7082D328, 0x7F592C4A, 0x4927A277};
	xword32 block[8];
	roundkey rkk;

	xrijndaelKeySched(key, 256, 256, &rkk);

	for(int i=0; i < 8; i ++) block[i] = pln[i];
    xrijndaelEncrypt(block, &rkk);
	for(int i=0; i < 8; i ++) printf("%x %x\n",block[i], cph[i]);
    xrijndaelDecrypt(block, &rkk);
	for(int i=0; i < 8; i ++) printf("%x %x\n",block[i], pln[i]);
    return 0;
}

