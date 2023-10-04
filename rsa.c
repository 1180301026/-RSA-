#include <stdio.h>
#include <stdlib.h>
#include <time.h>
 
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int  u32;
 
#if 0
//255以内的所有质数
u8 prime[] = {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 
	31, 37, 41, 43, 47, 53, 59, 61, 67, 
	71, 73, 79, 83, 89, 97, 101, 103, 113, 127,
	131, 137, 139, 149, 151, 157, 163, 167, 173, 181,
	191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 
	241, 251
};
#endif 
#if 1
//在2-255中随机获取一个质数
u8 get_rand_prime(void)
{
	u8 prime = 0;
	static u32 i = 0;
	do
	{		
		i++;
		srand((u32)(time(NULL)) + i);
		u8 rand_num = (rand() + 2 + i) % 255;
		//printf("rand = %d\n", rand_num);
		if((rand_num % 2) != 0)//筛选出单数，质数一定是单数
		{
			u8 temp = 3;
			for(temp = 3; temp < rand_num; temp += 2)
			{
				if(rand_num % temp == 0)
				{
					break;
				}
				if((rand_num % temp != 0) && (rand_num - temp) == 2)
				{
					//printf("找到质数 = %d\n",rand_num);
					prime = rand_num;
				}
			}
		}		
	}while(prime == 0 );
	return prime;
}
#endif
//获取两个不相同的质数，并且这两个质数的乘积大于255，小于4095
//乘积大于255是为了防止模运算的时候被除数大于除数，导致求的模结果（（被除数-除数）% 除数）溢出
//乘积小于4095是为了将密文限制在u16表示的范围内
void get_public_key_T(u32 *T, u32 *N, u32 *E)
{
	u8 temp1 = 0, temp2 = 0;
 
	u32 i, temp = 0;
	do
	{
		temp1 = get_rand_prime();
		temp2 = get_rand_prime();	
	}while((temp1 == temp2) || (temp1 * temp2 < 255) || (temp1 * temp2 > 4095));
	//printf("temp1 = %d, temp2 = %d\n", temp1, temp2);
	*T = (temp1 - 1) * (temp2 - 1);
	*N = temp1 * temp2;
 
	do
	{
		*E = ((u32)rand() + 3) % *T;
		temp = *E;
		for(i = 2; i <= *E; i++)
		{
			if(*E % i == 0 && *T % i == 0 && *E > 2)
			{
				break;
			}
		}
	}while(i <= temp || *E <= 2);
	//printf("E = %d, T = %d, N = %d\n", *E, *T, *N);
}
 
 
//求秘钥D
void get_d(unsigned int t, unsigned int e, unsigned int *d)
{
	u32 D = 1; 
	while(((e * D - 1) % t) != 0)
	{
		D++;
	}
	*d = D;
}
// 求 a^b mod c
unsigned int modpow(unsigned int a, unsigned int b, unsigned int c) 
{
	unsigned int res = 1;
	while(b > 0) 
	{
		if(b & 1) 
		{
			res = (res * a) % c;
		}
		b = b >> 1;
		a = (a * a) % c; 
	}
	return res;
}
 
//生成64个秘钥和公钥
void product_key(u32 *public_key, u32 *private_key, u32 *prime_product)
{
	int i = 0;
	u32 T[64] = {0};
	for(i = 0; i < 64; i++)
	{
		
		get_public_key_T(T + i, prime_product + i, public_key + i);
		get_d(T[i], public_key[i], private_key + i);
	}
}
int main()
{
#if 1
	u32 public_key[64], private_key[64], N[64];
	product_key(public_key, private_key, N);
 
	FILE* fp;
	fp = fopen("public_key.bin", "wb");
 
	printf("公钥:\n");
	for(int i = 1; i <= 64; i++)
	{		
		printf("0x%04x ", public_key[i - 1]);
		if(i % 10 == 0)
		{
			printf("\n");
		}
		int temp = public_key[i - 1 ] >> 8;
		int temp1 = (public_key[i - 1] << 8) >> 8;
		fwrite(&temp, sizeof(u8),1,fp);
		fwrite(&temp1, sizeof(u8),1,fp);
	}
 
	printf("\n私钥:\n");
	for(int i = 1; i <= 64; i++)
	{
		printf("0x%04x ", private_key[i - 1]);
		if(i % 10 == 0)
		{
			printf("\n");
		}
		int temp = private_key[i - 1] >> 8;
		int temp1 = (private_key[i - 1] << 8) >> 8;
		fwrite(&temp, sizeof(u8),1,fp);
		fwrite(&temp1, sizeof(u8),1,fp);
	}
 
	printf("\nN:\n");
	for(int i = 1; i <= 64; i++)
	{	
		printf("0x%04x ", N[i - 1]);
		if(i % 10 == 0)
		{
			printf("\n");
		}
		int temp = N[i - 1] >> 8;
		int temp1 = (N[i - 1] << 8) >> 8;
		fwrite(&temp, sizeof(u8),1,fp);
		fwrite(&temp1, sizeof(u8),1,fp);
	}
	printf("\n\n");
 
	printf("对生成的秘钥进行简单的测试：\n");
	for(int i = 0; i < 64; i++)
	{
		printf("原文 = %d ", i);
		unsigned int mw = modpow(i, public_key[i], N[i]);
		printf("密文 = %d ", mw);
		unsigned int mw_j = modpow(mw, private_key[i], N[i]);
		printf("解密 = %d\n", mw_j);
	}
 
	fclose(fp);
 
	//以二进制的方式打开文件，将文件内的内容读出
	printf("\n读出存储的公钥和秘钥以及N：\n");
	fp = fopen("public_key.bin", "rb");
	u8 ch = 0;
	int i = 0;
	for(i = 1; i <= 64 * 3 * 2; i++)
	{
		fread(&ch,sizeof(u8), 1, fp);
		printf("0x%02x ", ch);
		if(i % 10 == 0)
		{
			printf("\n");
		}
	}
	fclose(fp);
#endif
 
#if 1
 
 
#endif
	while(1);
 
}