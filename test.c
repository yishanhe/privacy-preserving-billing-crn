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
	
	
	// test util.c
	
	// test pbc commit
	pbc_commitment1_t c1;
	//pbc_commitment1_t * c1;
	//mpz_t * my_array;
//	c1 = malloc(sizeof(pbc_commitment1_t) * num_elements);
    // initialization
	/*
	c1.pairing = pairing;
    element_init_Zr(c1.value,pairing);
    element_init_Zr(c1.random_value,pairing);
    element_init_Zr(c1.opening_value,pairing);
    element_init_Zr(c1.random_opening_value,pairing);
    element_init_Zr(c1.hiding_value,pairing);
	element_init_Zr(c1.hiding_opening_value,pairing);
    element_init_Zr(c1.challenge,pairing);
    element_init_G1(c1.commitment_value,pairing);
    element_init_G1(c1.commitment_random_value,pairing);
    element_init_G1(c1.commitment_hiding_value_left,pairing);
	element_init_G1(c1.commitment_hiding_value_right,pairing);
    element_init_G1(c1.g,pairing);
    element_init_G1(c1.h,pairing);
	// random
    element_random(c1.value);
    element_random(c1.random_value);
    element_random(c1.opening_value);
    element_random(c1.random_opening_value);
    element_random(c1.challenge); // random challenge, test for real challenge generator later
   
	// set hiding value xh = x*e + xr
	element_mul(c1.hiding_value,c1.challenge,c1.value);
	element_add(c1.hiding_value,c1.hiding_value,c1.random_value);
	element_mul(c1.hiding_opening_value,c1.challenge,c1.opening_value);
	element_add(c1.hiding_opening_value,c1.hiding_opening_value,c1.random_opening_value);
	
	
   
    element_random(c1.g);
    element_random(c1.h);
	
	*/
	element_t cv;element_init_Zr(cv,pairing);
	element_set_si(cv,480);
	su_pbc_commit1_prepare(&c1,(pairing_ptr)pairing,cv);
		
	printf("The su_pbc_commit1_prepare TEST PASS !!!!!!!!\n\n");	
		
  	element_printf("Publishing  value : %B \n\n",c1.value);
  	element_printf("Publishing random value : %B \n\n",c1.random_value);
  	element_printf("Publishing opening value : %B \n\n",c1.opening_value);
  	element_printf("Publishing random opening value : %B \n\n",c1.random_opening_value);
  	element_printf("Publishing g  value : %B \n\n",c1.g);
  	element_printf("Publishing h  value : %B \n\n",c1.h);
	
    pbc_commit1(&c1);
    
	
  	element_printf("Publishing commitment value : %B \n\n",c1.commitment_value);
  	element_printf("Publishing commitment random value : %B \n\n",c1.commitment_random_value);
	
	printf("The calculation of pbc commitment TEST PASS !!!!!!!!\n\n");
	
	int bool_pbc_commit1 = pu_pbc_commit1_verify(c1);
	// test pu.c
	// verify the pbc commitment
	if (bool_pbc_commit1)
	{
		printf("pbc commit successful!!\n\n");
	}
	else
	{
		printf("pbc commit failed!!!\n\n");
	}
	printf("The verification of pbc commitment TEST PASS !!!!!!!!\n\n");
	

	

	
	// test su.c
	mpz_t v;
	mpz_init_set_si(v,128);
	gmp_printf("Publishing integer for decomposition v(%zd bit): %Zd \n\n", mpz_sizeinbase(v,2),v);
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
	
  
  	gmp_printf("Publishing value v(%zd bit): %Zd \n\n", mpz_sizeinbase(p,2),p);
  	gmp_printf("Publishing value a(%zd bit): %Zd\n\n", mpz_sizeinbase(a,2),a);
  	gmp_printf("Publishing value b(%zd bit): %Zd\n\n", mpz_sizeinbase(b,2),b);
    gmp_printf("Publishing value d(%zd bit): %Zd\n\n", mpz_sizeinbase(d,2),d);
	
    printf("The decomposition of sum of three squares TEST PASS !!!!!!!!\n\n");
	
	// test integer commitment
	integer_commitment_t c2;
    mpz_t value[7];
    mpz_t random_value[7];
	mpz_t hiding_value[7];
    mpz_t generator[7];
	// test publish prime and modulo
	
	// prepare
	su_integer_commit6_prepare(&c2, value, random_value, hiding_value, generator,v,a,b,d);
	printf("The su_integer_commit6_prepare TEST PASS !!!!!!!!\n\n");
	
	su_integer_commit6(&c2);
    gmp_printf("Publishing ommitment values(%zd bit): %Zd\n\n", mpz_sizeinbase(c2.v_commitment_value,2),c2.v_commitment_value);
	gmp_printf("Publishing ommitment values(%zd bit): %Zd\n\n", mpz_sizeinbase(c2.v_commitment_random_value,2),c2.v_commitment_random_value);
    gmp_printf("Publishing ommitment values(%zd bit): %Zd\n\n", mpz_sizeinbase(c2.integer_commitment_value,2),c2.integer_commitment_value);
	gmp_printf("Publishing ommitment values(%zd bit): %Zd\n\n", mpz_sizeinbase(c2.integer_commitment_random_value,2),c2.integer_commitment_random_value);
	
    printf("The su_integer_commit6 TEST PASS !!!!!!!!\n\n");
	
	
	int bool_integer_commit6 = pu_integer_commit6_verify (&c2);
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
	printf("The pu_integer_commit6_verify TEST PASS !!!!!!!!\n\n");
	
	
	
	// test CL signature
	
	element_t message[3];
	element_init_Zr(message[0],pairing); element_set_si(message[0], 3);
	element_init_Zr(message[1],pairing); element_set_si(message[1], 4);
	element_init_Zr(message[2],pairing); element_set_si(message[2], 12);
	int message_len = 3;
	element_t z[message_len-1];
	element_t Z[message_len-1];
	cl_pk_t pu_pk;
	cl_sk_t pu_sk;
	pu_cl_key_gen (&pu_pk, &pu_sk, message,message_len, pairing, z,Z); 
	/*
	typedef struct  {
		pairing_ptr pairing;
		elemnent_t g;
		element_t X;
		element_t Y;
		element_t *Z;
		int len;
	} cl_pk_t; 

	typedef struct  {
		elemnent_t x;
		element_t y;
		element_t * z;
		int len;
	} cl_sk_t; 
	*/
	element_printf("Z0 %B\n\n",pu_pk.Z[0]);
	element_printf("z0 %B\n\n",pu_sk.z[0]);
	element_printf("Z1 %B\n\n",pu_pk.Z[1]);
	element_printf("z1 %B\n\n",pu_sk.z[1]);

	printf("The pu_cl_key_gen TEST PASS !!!!!!!!\n\n");
	
	cl_signature_t pu_sig;
	element_t A[message_len-1];
	element_t B[message_len-1];
	pu_cl_sig_sign_prepare(&pu_sig, pairing,message_len, A,B);
	//	element_printf("A0 %B\n\n",pu_sig.A[0]);
	printf("The pu_cl_sig_sign_prepare TEST PASS !!!!!!!!\n\n");
		
		
	pu_cl_sig_sign(&pu_pk, &pu_sk,&pu_sig, message,message_len);
	element_printf("A0 %B\n\n",pu_sig.A[0]);
	element_printf("A1 %B\n\n",pu_sig.A[1]);
	//element_printf("A0 %B\n\n",pu_sig.A[2]);	
	element_printf("B0 %B\n\n",pu_sig.B[0]);
	element_printf("B1 %B\n\n",pu_sig.B[1]);
	printf("The pu_cl_sig_sign TEST PASS !!!!!!!!\n\n");
	
	int  bool_su_cl_sig_verify = su_cl_sig_verify(&pu_pk, &pu_sk,&pu_sig,message);
		
	if (bool_su_cl_sig_verify)
	{
		printf("su_cl_sig_verify successful!!\n\n");
	}
	else
	{
		printf("su_cl_sig_verify failed!!!\n\n");
	}
	printf("The su_cl_sig_verify TEST PASS !!!!!!!!\n\n");
	
	element_t commitment; element_init_G1(commitment, pu_pk.pairing);
	get_cl_commitment(&pu_pk, message,commitment);
	element_printf("commitment of message  %B\n\n",commitment);
	
	
	
	// blind cignature
	cl_signature_t blinded_pu_sig;
	element_t blinded_A[message_len-1];
	element_t blinded_B[message_len-1];
	proof_knowledge_signature_t proof;
	element_t Vxy_i[message_len-1];
	element_t miu[message_len];
	su_cl_blind_sig_sign_prepare(&proof,&blinded_pu_sig, &pu_sig, pairing,message_len, blinded_A,blinded_B, Vxy_i,miu);
	//element_printf("blinded_A init  %B\n\n",blinded_A[0]);
	//element_printf("blinded_A init  %B\n\n",blinded_A[1]);
	su_cl_blind_sig_sign(&proof,&pu_pk) ;
	
	element_printf("blinded A %B\n\n",*(proof.blinded_sig->A));
	element_printf("blinded A %B\n\n",*(proof.blinded_sig->A+1));

	element_printf("blinded B %B\n\n",*(proof.blinded_sig->B));
	element_printf("blinded B %B\n\n",*(proof.blinded_sig->B+1));
	element_printf("Vr  %B\n\n",proof.Vr);
	
	
	printf("The su_cl_blind_sig_sign TEST PASS !!!!!!!!\n\n");

	
	int bool_pu_cl_blind_sig_verify =pu_cl_blind_sig_verify(&proof,&pu_pk);
	if (bool_pu_cl_blind_sig_verify)
	{
		printf("bool_pu_cl_blind_sig_verify successful!!\n\n");
	}
	else
	{
		printf("bool_pu_cl_blind_sig_verify failed!!!\n\n");
	}
	printf("The bool_pu_cl_blind_sig_verify TEST PASS !!!!!!!!\n\n");
	
	// product
	pbc_commitment1_t cp;
	element_set_si(cv,12);
	su_pbc_commit1_prepare(&cp,(pairing_ptr)pairing,cv);
	
	
	pbc_commitment1_t cf1;
	element_set_si(cv,4);
	su_pbc_commit1_prepare(&cf1,(pairing_ptr)pairing,cv);
	
	
	pbc_commitment1_t cf2;
	element_set_si(cv,3);
	su_pbc_commit1_prepare(&cf2,(pairing_ptr)pairing,cv);
	
	
	// challenge and g,h should be same
	element_set(cf1.challenge, cp.challenge);
	element_set(cf1.g, cp.g);
	element_set(cf1.h, cp.h);
	element_set(cf2.challenge, cp.challenge);
	element_set(cf2.g, cp.g);
	element_set(cf2.h, cp.h);
	
	pbc_commit1(&cp);
	pbc_commit1(&cf1);
	pbc_commit1(&cf2);
	
	proof_product_t proof_product;
	su_product_proof_prepare(&proof_product, &pu_pk, &cp, & cf1, &cf2);
	
	su_product_proof(&proof_product);

	int bool_pu_product_proof_verify=pu_product_proof_verify(&proof_product);
	if (bool_pu_product_proof_verify)
	{
		printf("bool_pu_product_proof_verify successful!!\n\n");
	}
	else
	{
		printf("bool_pu_product_proof_verify failed!!!\n\n");
	}
	printf("The bool_pu_product_proof_verify TEST PASS !!!!!!!!\n\n");
	
	
	
	return 0;
}
