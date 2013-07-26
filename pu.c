#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <gmp.h>
#include "util.h"
/*
typedef struct  {
	pairing_ptr pairing;
	element_t value;
	element_t random_value;
	element_t opening_value;
	element_t random_opening_value;
	element_t hiding_value;
	element_t hiding_opening_value;
	element_t challenge;
	element_t g;
	element_t h;
	element_t commitment_value;	
	element_t commitment_random_value;
	element_t commitment_hiding_value_left;	
	element_t commitment_hiding_value_right;
} pbc_commitment1_t; // commitment strcuture for interval checking
	
*/
// @TODO total_fee_verify
int pu_sum_fee_verify(pbc_commitment1_t * c_fee1,pbc_commitment1_t * c_fee2,pbc_commitment1_t * sum_fee){
    int result=1;
	element_t left; element_init_G1(left,sum_fee->pairing);
	
	element_mul(left,c_fee1->commitment_value,c_fee2->commitment_value);
	
    // verify
    if (element_cmp(left,sum_fee->commitment_value)){
        result = 0;
		goto end;
    }
	
	end: 
	element_clear(left);
	return result;
}

/*
int pu_product_proof_verify(proof_product_t * proof_product){
	element_t left;
	element_t right;
	int result=1;
	element_init_G1(left,proof_product->pairing);
	element_init_G1(right,proof_product->pairing);
	
	//1
	element_printf("g %B\n\n",proof_product->cp->g);	
	element_printf("u1 %B\n\n",proof_product->u1);	
	element_printf("h %B\n\n",proof_product->cp->h);	
	element_printf("v1 %B\n\n",proof_product->v1);	
	element_pow2_zn(left,proof_product->cp->g,proof_product->u1,proof_product->cp->h,proof_product->v1);
	element_pow_zn(right,proof_product->cf1->commitment_value,proof_product->challenge);
	element_mul(right,right,proof_product->D1);	
	element_printf("right %B\n\n",right);
	element_printf("left %B\n\n",left);
	
	element_printf("challenge %B\n\n",proof_product->challenge);
	element_printf("u1 %B\n\n",proof_product->u1);
	element_printf("v1 %B\n\n",proof_product->v1);
	element_printf("u2 %B\n\n",proof_product->u2);
	element_printf("v2 %B\n\n",proof_product->v2);
	if (element_cmp(left, right)!=0) {
		printf("fail 1\n\n");
		result = 0;
	//	goto end;
	}
	//2
	element_pow2_zn(left,proof_product->cp->g,proof_product->u2,proof_product->cp->h,proof_product->v2);
	element_pow_zn(right,proof_product->cf2->commitment_value,proof_product->challenge);
	element_mul(right,right,proof_product->D2);	
	element_printf("right %B\n\n",right);
	element_printf("left %B\n\n",left);
	if (element_cmp(left, right)!=0) {
		printf("fail 2\n\n");
		result = 0;
	//	goto end;
	}
	//3
	element_pow2_zn(left, proof_product->cf1->commitment_value, proof_product->u2, proof_product->cp->h, proof_product->v3);
	element_pow_zn(right, proof_product->cp->commitment_value, proof_product->challenge);
	element_mul(right, right, proof_product->D3);
	if (element_cmp(left, right)!=0) {
		printf("fail 3\n\n");
		result = 0;
	//	goto end;
	}


	end:
	element_clear(left);	
	element_clear(right);	
	return result;
}
*/

int pu_product_proof_verify(proof_product_t * proof_product){
	element_t left;
	element_t right;
	int result=1;
	element_init_G1(left,proof_product->pairing);
	element_init_G1(right,proof_product->pairing);
	element_pow2_zn(left,proof_product->cp->g,proof_product->x1,proof_product->cp->h,proof_product->x2);
	element_pow_zn(right,proof_product->cf1->commitment_value,proof_product->challenge);
	element_mul(right,right,proof_product->R1);	

	if (element_cmp(left, right)!=0) {
		result = 0;
		goto end;
	}
	
	element_pow2_zn(left, proof_product->cf2->commitment_value, proof_product->x1, proof_product->cp->h, proof_product->x3);
	element_pow_zn(right, proof_product->cp->commitment_value, proof_product->challenge);
	element_mul(right, right, proof_product->R2);

	if (element_cmp(left, right)!=0) {
		result = 0;
		goto end;
	}

	end:
	element_clear(left);	
	element_clear(right);	
	return result;
}

int pu_cl_blind_sig_verify(proof_knowledge_signature_t * proof, cl_pk_t * pu_pk){
	// verify the proof
	int result=1;
	int i;
	int l = pu_pk->len-1;
	element_t Vsp;
	element_init_GT(Vsp,pu_pk->pairing);
	element_t left_T; //GT
	element_init_GT(left_T,pu_pk->pairing);
	element_t right_T;
	element_init_GT(right_T,pu_pk->pairing);
	
	//vs^p p=rr;
	element_pow_zn(Vsp,proof->Vs,proof->rr);
	int bool_proof_verify=element_cmp(Vsp,proof->Vr);
	//printf("test %d",bool_proof_verify);
	//int count=0;
	if(bool_proof_verify!=1){
	//	printf("fail %d",++count);
		result=0;
		goto end;
	}
	//test

	//
	pairing_pp_t pp1;
	pairing_pp_init(pp1,pu_pk->g,pu_pk->pairing); //g
	
	pairing_pp_t pp2;
	pairing_pp_init(pp2,proof->blinded_sig->a,pu_pk->pairing);//ar
	
	pairing_pp_t pp3;
	pairing_pp_init(pp3,pu_pk->Y,pu_pk->pairing);//Y
	
	// e(ar,Y) e(g,br)
	pairing_pp_apply(left_T,pu_pk->Y,pp2);
	pairing_pp_apply(right_T,proof->blinded_sig->b,pp1);
	if (element_cmp(right_T, left_T)!=0) {
		//printf("fail %d\n\n",++count);
		result = 0;
		goto end;
	}
	
	for(i=0;i<l;i++){
		pairing_pp_apply(left_T,*(pu_pk->Z+i),pp2);
		pairing_pp_apply(right_T,*(proof->blinded_sig->A+i),pp1);
		if (element_cmp(right_T, left_T)!=0) {
		//	printf("fail %d\n\n",++count);
			result = 0;
			goto end;
		}
		pairing_pp_apply(left_T,*(proof->blinded_sig->A+i),pp3);
		pairing_pp_apply(right_T,*(proof->blinded_sig->B+i),pp1);
		if (element_cmp(right_T, left_T)!=0) {
		//	printf("fail %d\n\n",++count);
			result = 0;
			goto end;
		}
		
	}
	
	
	
	
	
	end:
	pairing_pp_clear(pp1);
	pairing_pp_clear(pp2);
	pairing_pp_clear(pp3);
	element_clear(Vsp);
	element_clear(right_T);
	element_clear(left_T);
	return result;
	
}
	// generate public key and private key
	
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
	
	// cl_pk_t initial

void pu_cl_key_gen (cl_pk_t * pu_pk, cl_sk_t * pu_sk, element_t * message,int message_len, pairing_ptr pairing,element_t * z, element_t * Z) {
	pu_pk->len = message_len;
	pu_sk->len = message_len;
	pu_sk->z=z;
	pu_pk->Z=Z;		
	// initial private key 
	element_init_Zr(pu_sk->x,pairing);
	element_random(pu_sk->x);
	element_init_Zr(pu_sk->y,pairing);
	element_random(pu_sk->y);
	int i;
	for (i=0;i<pu_sk->len-1;i++){
		element_init_Zr(*(pu_sk->z+i),pairing);
		element_random(*(pu_sk->z+i));
	}
	
	
	// initial public key
	pu_pk->pairing = pairing;
	element_init_G1(pu_pk->g, pairing);
	element_random(pu_pk->g);
	element_init_G1(pu_pk->X, pairing);
	element_init_G1(pu_pk->Y, pairing);
	element_pow_zn(pu_pk->X,pu_pk->g,pu_sk->x);
	element_pow_zn(pu_pk->Y,pu_pk->g,pu_sk->y);
	for (i=0;i<pu_pk->len-1;i++){
		element_init_G1(*(pu_pk->Z+i), pairing);
		element_pow_zn(*(pu_pk->Z+i),pu_pk->g,*(pu_sk->z+i));
	}
	
	// cl_sk_t initial
	
}


int pu_integer_commit6_verify(integer_commitment_t *c){
	
	
	/*
	mpz_t integer_commitment_value;
	mpz_t integer_commitment_random_value;
	mpz_t integer_commitment_hiding_value_left;
	mpz_t integer_commitment_hiding_value_right;
	// commit v
	mpz_t v_commitment_value;
	mpz_t v_commitment_random_value;
	mpz_t v_commitment_hiding_value_left;
	mpz_t v_commitment_hiding_value_right;
	*/
	// commit 1 verify
	
	// left
    mpz_powm(c->v_commitment_hiding_value_left,c->v_commitment_value,c->challenge,c->n);
    mpz_mul(c->v_commitment_hiding_value_left,c->v_commitment_hiding_value_left,c->v_commitment_random_value);
    mpz_mod(c->v_commitment_hiding_value_left,c->v_commitment_hiding_value_left,c->n);
   
	// right
	mpz_t(commit1_tmp1);
	mpz_init(commit1_tmp1);
	mpz_t(commit1_tmp2);
	mpz_init(commit1_tmp2);
	
	mpz_powm (commit1_tmp1, *(c->generator),  *(c->hiding_value),  c->n);// g^hv mod n
    mpz_powm (commit1_tmp2, *(c->generator+6),  *(c->hiding_value+6),  c->n); //h^hR mod n
    mpz_mul(c->v_commitment_hiding_value_right,commit1_tmp1,commit1_tmp1);
    mpz_mod(c->v_commitment_hiding_value_right,c->v_commitment_hiding_value_right,c->n);
	// free
	mpz_clear(commit1_tmp1);
	mpz_clear(commit1_tmp2);
	
	// commit 6 verify
	//left
    mpz_powm(c->integer_commitment_hiding_value_left,c->integer_commitment_value,c->challenge,c->n);
    mpz_mul(c->integer_commitment_hiding_value_left,c->integer_commitment_hiding_value_left,c->integer_commitment_random_value);
    mpz_mod(c->integer_commitment_hiding_value_left,c->integer_commitment_hiding_value_left,c->n);
	//right
	mpz_t integer_commit6_tmp1;
	mpz_t integer_commit6_tmp2;
	mpz_init(integer_commit6_tmp1);
	mpz_init(integer_commit6_tmp2);
	mpz_powm (integer_commit6_tmp1,  *(c->generator),  *(c->hiding_value),  c->n);
	int i;
	for(i = 1; i < c->len-1; i++){
		mpz_powm (integer_commit6_tmp2,  *(c->generator+i),  *(c->hiding_value+i),  c->n);
	    mpz_mul(integer_commit6_tmp1,integer_commit6_tmp1,integer_commit6_tmp2);
	    mpz_mod(integer_commit6_tmp1,integer_commit6_tmp1,c->n);
	}
	mpz_set(c->integer_commitment_hiding_value_right,integer_commit6_tmp1);
	// free
	mpz_clear(integer_commit6_tmp1);
	mpz_clear(integer_commit6_tmp2);	
	
	
	if ( (mpz_cmp(c->integer_commitment_hiding_value_right,c->integer_commitment_hiding_value_left)==0 )&&(mpz_cmp(c->v_commitment_hiding_value_right,c->v_commitment_hiding_value_left)==0 ))
	{
		return 1;
	}
	else
	{
		return 0;
	}
	
	
}	


int pu_pbc_commit1_verify(pbc_commitment1_t c){
	// verify the leftvalue and right value
	// calculate the left value
	element_pow_zn(c.commitment_hiding_value_left,c.commitment_value,c.challenge);
	element_mul(c.commitment_hiding_value_left,c.commitment_hiding_value_left,c.commitment_random_value);
	// calculate the right value
	// g^(e*x+xr) * h^(e*ox+oxr)

	element_pow2_zn(c.commitment_hiding_value_right,c.g,c.hiding_value,c.h,c.hiding_opening_value);
	
	//verify
	if (element_cmp(c.commitment_hiding_value_right,c.commitment_hiding_value_left)==0)
	{
		return 1;
	}
	else
	{
		return 0;
	}

}
/*
typedef struct  {
	element_t a;
	element_t * A;
	element_t b;
	element_t * B;
	element_t c;
	int len;	
} cl_signature_t; 
*/


void pu_cl_sig_sign_prepare(cl_signature_t * pu_sig, pairing_ptr pairing,int message_len, element_t * A,element_t * B) {
	// need to specify the A and B when call this function
	pu_sig->len=message_len;
	pu_sig->A=A;
	pu_sig->B=B;
	element_init_G1(pu_sig->a,pairing);
	element_init_G1(pu_sig->b,pairing);
	element_init_G1(pu_sig->c,pairing);
	int i;
	for (i=0;i<pu_sig->len-1;i++) {
		element_init_G1(*(pu_sig->A+i),pairing);
		element_init_G1(*(pu_sig->B+i),pairing);
	}
}



void pu_cl_sig_sign(cl_pk_t * pu_pk, cl_sk_t * pu_sk,cl_signature_t * pu_sig, element_t message[],int message_len) {
	
	int i; // for loop
	
	
	
	// xy = x * y
	element_t xy; element_init_Zr(xy, pu_pk->pairing);
	element_mul(xy, pu_sk->x, pu_sk->y);

	// b = a ^ y
	element_random(pu_sig->a);
	element_pow_zn(pu_sig->b, pu_sig->a, pu_sk->y);

	// c = a ^ (x + x * y * m_0)
	// e= x+x*y*m_0
	element_t e; element_init_Zr(e, pu_pk->pairing);
	element_mul(e, xy, message[0]);
	element_add(e, e, pu_sk->x);
	element_pow_zn(pu_sig->c, pu_sig->a, e);
	
	element_t f; element_init_G1(f, pu_pk->pairing);
	for (i = 0; i < pu_sig->len-1; i++) {
		
		// A = a ^ z
		element_pow_zn(*(pu_sig->A+i), pu_sig->a, *(pu_sk->z+i));
		
		// B = A ^ y
		element_pow_zn(*(pu_sig->B+i), *(pu_sig->A+i), pu_sk->y);
		
		// C *= A ^ (x * y * m_{i + 1})
		element_mul(e, xy, message[1 + i]);
		element_pow_zn(f, *(pu_sig->A+i), e);
		element_mul(pu_sig->c, pu_sig->c, f);
	}

	element_clear(xy);
	element_clear(e);
	element_clear(f);
}


