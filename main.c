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
	double t0=pbc_get_time();
	publish_modulus(n, prime1, prime2);
	double t1=pbc_get_time();
	printf("Pre-stage: Publish primes and modulos. %lf ms\n\n",(t1-t0)*1000.0);	
	
	
	// load parameters
	pairing_t pairing;
	
	FILE* fparam = fopen("a.param", "rb");
	char param[1024];
	size_t count = fread(param, 1, 1024, fparam);
	fclose(fparam);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
	
	int message_len = 3;
	//@TODO publish g h and maybe the hash 
	
	/******************** sign policy 1****************************************/
	
	// test CL signature
	printf("Stage1: PU sign the policy with CL singature\n\n");
	
	element_t policy_tuple[3];
	element_init_Zr(policy_tuple[0],pairing); element_set_si(policy_tuple[0], 0); // 0-12:00
	element_init_Zr(policy_tuple[1],pairing); element_set_si(policy_tuple[1], 720); //
	element_init_Zr(policy_tuple[2],pairing); element_set_si(policy_tuple[2], 5);
	int policy_tuple_len = 3;
	element_t z[policy_tuple_len-1];
	element_t Z[policy_tuple_len-1];
	cl_pk_t pu_pk;
	cl_sk_t pu_sk;
	t0=pbc_get_time();
	pu_cl_key_gen (&pu_pk, &pu_sk, policy_tuple,policy_tuple_len, pairing, z,Z); 
	t1=pbc_get_time();
	printf("1.1 PU generates the keys %lf ms \n\n",(t1-t0)*1000.0);
	
	cl_signature_t pu_sig;
	element_t A[policy_tuple_len-1];
	element_t B[policy_tuple_len-1];
	pu_cl_sig_sign_prepare(&pu_sig, pairing,policy_tuple_len, A,B);

		
	t0=pbc_get_time();
	pu_cl_sig_sign(&pu_pk, &pu_sk,&pu_sig, policy_tuple,policy_tuple_len);
	t1=pbc_get_time();
	printf("1.2 PU signs a single policy %lf ms \n\n",(t1-t0)*1000.0);
	
	t0=pbc_get_time();
	int  bool_su_cl_sig_verify = su_cl_sig_verify(&pu_pk, &pu_sk,&pu_sig,policy_tuple);
	t1=pbc_get_time();
	printf("1.3 SU verifies a single policy %lf ms \n\n",(t1-t0)*1000.0);
			
	
	if (bool_su_cl_sig_verify)
	{
		printf("policy signature verify successful!!\n\n");
	}
	else
	{
		printf("policy signature verify failed!!!\n\n");
	}
	

	
	

	printf("Stage2: SU makes pbc commits towards its consumption tuple. \n\n");
	
	
	
	
	// test pbc commit
	pbc_commitment1_t c_t1;
	pbc_commitment1_t c_delta_t1;
	pbc_commitment1_t c_fee1;
	pbc_commitment1_t c_fee2;
	pbc_commitment1_t unit_price;
	pbc_commitment1_t sum_fee;
	
	
	element_t value1;element_init_Zr(value1,pairing);
	element_t value2;element_init_Zr(value2,pairing);
	element_t value3;element_init_Zr(value3,pairing);
	element_t value4;element_init_Zr(value4,pairing);
	element_t value5;element_init_Zr(value5,pairing);
	element_t value6;element_init_Zr(value6,pairing);
	
	element_set_si(value1,480); //08:00
	element_set_si(value2,3); // 1000 mins
	element_set_si(value3,15); // fee1
	element_set_si(value4,24); // fee2
	element_set_si(value5,39); // sum_fee is the total fee
	element_set_si(value6,5); // unit price is the total fee
	
	su_pbc_commit1_prepare(&c_t1,(pairing_ptr)pairing,value1);
	su_pbc_commit1_prepare(&c_delta_t1,(pairing_ptr)pairing,value2);
	su_pbc_commit1_prepare(&c_fee1,(pairing_ptr)pairing,value3);
	su_pbc_commit1_prepare(&c_fee2,(pairing_ptr)pairing,value4);
	su_pbc_commit1_prepare(&sum_fee,(pairing_ptr)pairing,value5);
	su_pbc_commit1_prepare(&unit_price,(pairing_ptr)pairing,value6);
	
	
	//@TODO manuly set the same g h and challenge for late the product
	
	//element_set(c_delta_t1.challenge, c_t1.challenge);
	element_set(c_delta_t1.g, c_t1.g);
	element_set(c_delta_t1.h, c_t1.h);
	//element_set(c_fee1.challenge, c_t1.challenge);
	element_set(c_fee1.g, c_t1.g);
	element_set(c_fee1.h, c_t1.h);
	//element_set(c_fee2.challenge, c_t1.challenge);
	element_set(c_fee2.g, c_t1.g);
	element_set(c_fee2.h, c_t1.h);
	//element_set(sum_fee.challenge, c_t1.challenge);
	element_set(sum_fee.g, c_t1.g);
	element_set(sum_fee.h, c_t1.h);
	//element_set(unit_price.challenge, c_t1.challenge);
	element_set(unit_price.g, c_t1.g);
	element_set(unit_price.h, c_t1.h);
	
	// for total fee verification
	element_add(sum_fee.opening_value,c_fee1.opening_value,c_fee2.opening_value);
	element_mul(sum_fee.hiding_opening_value,sum_fee.challenge,sum_fee.opening_value);
	element_add(sum_fee.hiding_opening_value,sum_fee.hiding_opening_value,sum_fee.random_opening_value);
	
	/*
	element_printf("gh %B\n\n",c_delta_t1.g);
	element_printf("gh %B\n\n",c_fee1.g);
	element_printf("gh %B\n\n",c_fee2.g);
	element_printf("gh %B\n\n",sum_fee.g);
	element_printf("gh %B\n\n",unit_price.g);
	*/
	
	t0=pbc_get_time();
    pbc_commit1(&c_t1);
    pbc_commit1(&c_delta_t1);
	pbc_commit1(&c_fee1);
	t1=pbc_get_time();
	printf("2.1 Integer commit a tuple of [t,delta_t,fee]_i (three commitments) %lf ms \n\n",(t1-t0)*1000.0);
	
	pbc_commit1(&c_fee2);
	pbc_commit1(&unit_price);
	
	t0=pbc_get_time();
	pbc_commit1(&sum_fee); 
	t1=pbc_get_time();
	printf("2.2 Integer commit total fee time consume(single commitments) %lf ms \n\n",(t1-t0)*1000.0);
 
	

	t0=pbc_get_time();
	int bool_pbc_commit_t1 = pu_pbc_commit1_verify(c_t1);
	int bool_pbc_commit_delta_t1 = pu_pbc_commit1_verify(c_delta_t1);
	int bool_pbc_commit_fee1 = pu_pbc_commit1_verify(c_fee1);
	t1=pbc_get_time();
	printf("2.3 Verify a tuple of commmitment[t,delta_t,fee]_i %lf ms \n\n",(t1-t0)*1000.0);
	
	t0=pbc_get_time();
	int bool_pbc_commit_sum_fee = pu_pbc_commit1_verify(sum_fee);
	t1=pbc_get_time();
	printf("2.4 Verify a total fee %lf ms \n\n",(t1-t0)*1000.0);
	
	
	// test pu.c
	// verify the pbc commitment
	//&&bool_pbc_commit_fee3
	if (bool_pbc_commit_t1&&bool_pbc_commit_delta_t1&&bool_pbc_commit_fee1&&bool_pbc_commit_sum_fee)
	{
		printf("policy verify successful!!\n\n");
	}
	else
	{
		printf("policy verify failed!!!\n\n");
	}
		
		
		
	
	/*************************************************************************/
	/******************************* bound checking ***************************/
	/*************************************************************************/
	printf("Stage3: SU makes integer commits and prove the interval checking\n\n");
	
    //left bound
	mpz_t v;
	mpz_init_set_si(v,480);
	
	if(mpz_sgn(v)==-1){
		pbc_die("integer for decompostion is negetive!");
	}


	t0=pbc_get_time();
	mpz_t a; mpz_init(a);
	mpz_t b; mpz_init(b);
	mpz_t d; mpz_init(d);
    
  	mpz_t p; mpz_init_set_si(p,1); // p=4*v+1
  	mpz_t ptmp; mpz_init(ptmp); // p=4*v+1
    mpz_mul_si(ptmp,v,4);
  	mpz_add(p,ptmp,p);
	sum_of_squares(a,b,d,p);
	t1=pbc_get_time();
	printf("3.1 SU decomposites the value to sum of three squares %lf ms \n\n",(t1-t0)*1000.0);
  
	
	//integer commitment
	integer_commitment_t c2;
    mpz_t value[7];
    mpz_t random_value[7];
	mpz_t hiding_value[7];
    mpz_t generator[7];
	// test publish prime and modulo
	
	// prepare
	
	su_integer_commit6_prepare(&c2, value, random_value, hiding_value, generator,v,a,b,d,n,prime1,prime2);
	
	t0=pbc_get_time();
	su_integer_commit6(&c2);
	t1=pbc_get_time();
	printf("3.2 SU generates an integer commitment(double commit) %lf ms \n\n",(t1-t0)*1000.0);

	
	t0=pbc_get_time();
	int bool_integer_commit6 = pu_integer_commit6_verify (&c2);
	t1=pbc_get_time();
	printf("3.3 PU verifies an integer commitment(double commit) %lf ms \n\n",(t1-t0)*1000.0);
	
	if (bool_integer_commit6)
	{
		printf("integer commit successful!!\n\n");
	}
	else
	{
		printf("integer commit failed!!!\n\n");
	}
	

	/*************************************************************************/
	/***********************  possession of signature ***********************/
	/*************************************************************************/
	printf("Stage4: SU proves its possession of the signature\n\n");
	
	// blind cignature
	cl_signature_t blinded_pu_sig;
	element_t blinded_A[message_len-1];
	element_t blinded_B[message_len-1];
	proof_knowledge_signature_t proof;
	element_t Vxy_i[message_len-1];
	element_t miu[message_len];
	su_cl_blind_sig_sign_prepare(&proof,&blinded_pu_sig, &pu_sig, pairing,message_len, blinded_A,blinded_B, Vxy_i,miu);
	t0=pbc_get_time();
	su_cl_blind_sig_sign(&proof,&pu_pk) ;
	t1=pbc_get_time();
	printf("4.1 SU generates the blinded signature %lf ms \n\n",(t1-t0)*1000.0);
	
	t0=pbc_get_time();
	int bool_pu_cl_blind_sig_verify =pu_cl_blind_sig_verify(&proof,&pu_pk);
	t1=pbc_get_time();
	printf("4.2 PU verifies the blinded signature %lf ms \n\n",(t1-t0)*1000.0);
	if (bool_pu_cl_blind_sig_verify)
	{
		printf("bool_pu_cl_blind_sig_verify successful!!\n\n");
	}
	else
	{
		printf("bool_pu_cl_blind_sig_verify failed!!!\n\n");
	}
	
	// multiplication
	
	// product
	
	/*
	pbc_commitment1_t cp;
	element_set_si(cv,12);
	su_pbc_commit1_prepare(&cp,(pairing_ptr)pairing,cv);
	// above should be substitude by the fee1
	
	pbc_commitment1_t cf1;
	element_set_si(cv,4);
	su_pbc_commit1_prepare(&cf1,(pairing_ptr)pairing,cv);
	// above should be substitude by the delta_time
	
	pbc_commitment1_t cf2;
	element_set_si(cv,3);
	su_pbc_commit1_prepare(&cf2,(pairing_ptr)pairing,cv);
	// above should be substitude by the price
	*/
	
	
	/*************************************************************************/
	/******************************  product  ********************************/
	/*************************************************************************/
	printf("Stage5: SU proves the product of delta time and price is correct fee \n\n");
	
	proof_product_t proof_product;
	//element_printf("test unit_price %B\n\n",unit_price.value);
	su_product_proof_prepare(&proof_product, &pu_pk, &c_fee1, &unit_price, &c_delta_t1);
	
	t0=pbc_get_time();
	su_product_proof(&proof_product);
	t1=pbc_get_time();
	printf("5.1 SU proves the product %lf ms \n\n",(t1-t0)*1000.0);

	t0=pbc_get_time();
	int bool_pu_product_proof_verify=pu_product_proof_verify(&proof_product);
	t1=pbc_get_time();
	printf("5.2 PU verifies the product %lf ms \n\n",(t1-t0)*1000.0);
	
	if (bool_pu_product_proof_verify==1)
	{
		printf("bool_pu_product_proof_verify successful!!\n\n");
	}
	else
	{
		printf("bool_pu_product_proof_verify failed!!!\n\n");
	}

	
	/*************************************************************************/
	/******************************  total bill  ********************************/
	/*************************************************************************/

	printf("Stage6: PU verifies the total fees  \n\n");

    t0=pbc_get_time(); 

	int bool_pu_sum_fee_verify=pu_sum_fee_verify(&c_fee1,&c_fee2,&sum_fee);
    t1=pbc_get_time(); 
	printf("6.1 PU verifies total fees %lf ms \n\n",(t1-t0)*1000.0);
       
	if (bool_pu_sum_fee_verify==1){
		printf("total fee verify pass\n\n");
	} else {
		printf("total fee verify failed\n\n");
	}

	return 0;

	
}
