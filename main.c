#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h> //using to get HASH for NIKP
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <gmp.h>
#include <sys/time.h>
#include "util.h"





int main (int argc, char const *argv[])
{
	
	mpz_t n; mpz_init(n);
	mpz_t prime1; mpz_init(prime1);
	mpz_t prime2; mpz_init(prime2);
	publish_modulus(n, prime1, prime2);
		
	// load parameters
	pairing_t pairing;
	
	FILE* fparam = fopen("a.param", "rb");
	char param[1024];
	size_t count = fread(param, 1, 1024, fparam);
	fclose(fparam);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
	
	
	/******************** sign policy ****************************************/
	
	// test CL signature
	
	element_t message[3];
	element_init_Zr(message[0],pairing); element_set_si(message[0], 0); // 0-12:00
	element_init_Zr(message[1],pairing); element_set_si(message[1], 720); //
	element_init_Zr(message[2],pairing); element_set_si(message[2], 5);
	int message_len = 3;
	element_t z[message_len-1];
	element_t Z[message_len-1];
	cl_pk_t pu_pk;
	cl_sk_t pu_sk;
	pu_cl_key_gen (&pu_pk, &pu_sk, message,message_len, pairing, z,Z); 

	
	cl_signature_t pu_sig;
	element_t A[message_len-1];
	element_t B[message_len-1];
	pu_cl_sig_sign_prepare(&pu_sig, pairing,message_len, A,B);

		
	double t0=pbc_get_time();
	pu_cl_sig_sign(&pu_pk, &pu_sk,&pu_sig, message,message_len);
	double t1=pbc_get_time();
	printf("Sign a single policy time consume is %lf ms \n\n",(t1-t0)*1000.0);
	
	t0=pbc_get_time();
	int  bool_su_cl_sig_verify = su_cl_sig_verify(&pu_pk, &pu_sk,&pu_sig,message);
	t1=pbc_get_time();
	printf("Verify a single policy time consume is %lf ms \n\n",(t1-t0)*1000.0);
			
	if (bool_su_cl_sig_verify)
	{
		printf("policy signature verify successful!!\n\n");
	}
	else
	{
		printf("policy signature verify failed!!!\n\n");
	}

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	// test pbc commit
	pbc_commitment1_t c_t1;
	pbc_commitment1_t c_delta_t1;
	pbc_commitment1_t c_fee1;
	pbc_commitment1_t c_fee2;
	pbc_commitment1_t c_fee3;
	
	
	element_t value1;element_init_Zr(value1,pairing);
	element_t value2;element_init_Zr(value2,pairing);
	element_t value3;element_init_Zr(value3,pairing);
	element_t value4;element_init_Zr(value4,pairing);
	element_t value5;element_init_Zr(value5,pairing);
	
	element_set_si(value1,480); //08:00
	element_set_si(value2,700); // 1000 mins
	element_set_si(value3,1100); // fee1
	element_set_si(value4,5000); // fee2
	element_set_si(value5,6100); // fee3 is the total fee
	
	su_pbc_commit1_prepare(&c_t1,(pairing_ptr)pairing,value1);
	su_pbc_commit1_prepare(&c_delta_t1,(pairing_ptr)pairing,value2);
	su_pbc_commit1_prepare(&c_fee1,(pairing_ptr)pairing,value3);
	su_pbc_commit1_prepare(&c_fee2,(pairing_ptr)pairing,value4);
	su_pbc_commit1_prepare(&c_fee3,(pairing_ptr)pairing,value5);
  	/*
	element_printf("Publishing  value : %B \n\n",c_t1.value);
  	element_printf("Publishing random value : %B \n\n",c_t1.random_value);
  	element_printf("Publishing opening value : %B \n\n",c_t1.opening_value);
  	element_printf("Publishing random opening value : %B \n\n",c_t1.random_opening_value);
  	element_printf("Publishing g  value : %B \n\n",c_t1.g);
  	element_printf("Publishing h  value : %B \n\n",c_t1.h);
	*/

	
	t0=pbc_get_time();
    pbc_commit1(&c_t1);
    pbc_commit1(&c_delta_t1);
	pbc_commit1(&c_fee1);
	t1=pbc_get_time();
	printf("Commit a tuple of [t,delta_t,fee]_i time consume is %lf ms \n\n",(t1-t0)*1000.0);
	
	pbc_commit1(&c_fee2);
	
	t0=pbc_get_time();
	pbc_commit1(&c_fee3); 
	t1=pbc_get_time();
	printf("Commit total fee time consume is %lf ms \n\n",(t1-t0)*1000.0);
 
	

	t0=pbc_get_time();
	int bool_pbc_commit_t1 = pu_pbc_commit1_verify(c_t1);
	int bool_pbc_commit_delta_t1 = pu_pbc_commit1_verify(c_delta_t1);
	int bool_pbc_commit_fee1 = pu_pbc_commit1_verify(c_fee1);
	t1=pbc_get_time();
	printf("Verify a tuple of commmitment[t,delta_t,fee]_i time consume is %lf ms \n\n",(t1-t0)*1000.0);
	
	t0=pbc_get_time();
	int bool_pbc_commit_fee3 = pu_pbc_commit1_verify(c_fee3);
	t1=pbc_get_time();
	printf("Verify a total fee time consume is %lf ms \n\n",(t1-t0)*1000.0);
	
	
	// test pu.c
	// verify the pbc commitment
	//&&bool_pbc_commit_fee3
	if (bool_pbc_commit_t1&&bool_pbc_commit_delta_t1&&bool_pbc_commit_fee1)
	{
		printf("policy verify successful!!\n\n");
	}
	else
	{
		printf("policy verify failed!!!\n\n");
	}
		
		
	
	

	
	// test su.c
	// leftbound
	//double ictime=0; //interval checking time
	//t0=pbc_get_time();
	mpz_t v;
	mpz_init_set_si(v,480);
	//gmp_printf("Publishing integer for decomposition v(%zd bit): %Zd \n\n", mpz_sizeinbase(v,2),v);
	if(mpz_sgn(v)==-1){
		pbc_die("integer for decompostion is negetive!");
	}
	//mpz_t p;mpz_init(p);
	
	//mpz_set(p,integer_for_decomposition);
	//gmp_printf(" %Zd \n\n", mpz_sizeinbase(p,2),p);
	mpz_t a; mpz_init(a);
	mpz_t b; mpz_init(b);
	mpz_t d; mpz_init(d);
    
  	mpz_t p; mpz_init_set_si(p,1); // p=4*v+1
  	mpz_t ptmp; mpz_init(ptmp); // p=4*v+1
    mpz_mul_si(ptmp,v,4);
  	mpz_add(p,ptmp,p);
	sum_of_squares(a,b,d,p);
//	t1=pbc_get_time();
//	ictime+=(t1-t0);
  
 // 	gmp_printf("Publishing value v(%zd bit): %Zd \n\n", mpz_sizeinbase(p,2),p);
  //	gmp_printf("Publishing value a(%zd bit): %Zd\n\n", mpz_sizeinbase(a,2),a);
 // 	gmp_printf("Publishing value b(%zd bit): %Zd\n\n", mpz_sizeinbase(b,2),b);
 //   gmp_printf("Publishing value d(%zd bit): %Zd\n\n", mpz_sizeinbase(d,2),d);
	
 //   printf("The decomposition of sum of three squares TEST PASS !!!!!!!!\n\n");
	
	// test integer commitment
	integer_commitment_t c2;
    mpz_t value[7];
    mpz_t random_value[7];
	mpz_t hiding_value[7];
    mpz_t generator[7];
	// test publish prime and modulo
	
	// prepare
	su_integer_commit6_prepare(&c2, value, random_value, hiding_value, generator,v,a,b,d);
//	printf("The su_integer_commit6_prepare TEST PASS !!!!!!!!\n\n");
	
	t0=pbc_get_time();
	su_integer_commit6(&c2);
	t1=pbc_get_time();
	printf("Generate an integer commitment(double commit) time consume is %lf ms \n\n",(t1-t0)*1000.0);
 //   gmp_printf("Publishing ommitment values(%zd bit): %Zd\n\n", mpz_sizeinbase(c2.v_commitment_value,2),c2.v_commitment_value);
//	gmp_printf("Publishing ommitment values(%zd bit): %Zd\n\n", mpz_sizeinbase(c2.v_commitment_random_value,2),c2.v_commitment_random_value);
//    gmp_printf("Publishing ommitment values(%zd bit): %Zd\n\n", mpz_sizeinbase(c2.integer_commitment_value,2),c2.integer_commitment_value);
//	gmp_printf("Publishing ommitment values(%zd bit): %Zd\n\n", mpz_sizeinbase(c2.integer_commitment_random_value,2),c2.integer_commitment_random_value);
	
//    printf("The su_integer_commit6 TEST PASS !!!!!!!!\n\n");
	
	t0=pbc_get_time();
	int bool_integer_commit6 = pu_integer_commit6_verify (&c2);
	t1=pbc_get_time();
	printf("Verify an integer commitment(double commit) time consume is %lf ms \n\n",(t1-t0)*1000.0);
	
	// test pu.c
	// verify the pbc commitment
	if (bool_integer_commit6)
	{
		printf("integer commit successful!!\n\n");
	}
	else
	{
		printf("integer commit failed!!!\n\n");
	}
	
	
	
	// verify total bill
	
	
	
	


	return 0;

	
}
