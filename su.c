#include <gmp.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include "util.h"



/*
typedef struct {
	pairing_ptr pairing;
	element_t p;
	element_t f1;
	element_t f2;
	element_t R1;
	element_t R2;
	element_t x1; // f1的hiding value
	element_t x2;
	element_t x3;
	element_t challenge;
	pbc_commitment1_t * cp;
	pbc_commitment1_t * cf1;
	pbc_commitment1_t * cf2;
	int len;
} proof_product_t;
*/
void su_product_proof(proof_product_t * proof_product){
	// R1
	element_pow2_zn(proof_product->R1,proof_product->cp->g,proof_product->cf1->random_value,proof_product->cp->h,proof_product->cf2->random_value);
	
	// R2
	element_pow2_zn(proof_product->R2,proof_product->cf2->commitment_value,proof_product->cf1->random_value,proof_product->cp->h,proof_product->cp->random_value);
		
	// x_2
	element_mul(proof_product->x2,proof_product->challenge,proof_product->cf1->opening_value);
	element_add(proof_product->x2,proof_product->x2,proof_product->cf2->random_value);
	// x_3
	element_mul(proof_product->x3,proof_product->cf2->opening_value,proof_product->f1);
	element_sub(proof_product->x3,proof_product->cp->opening_value,proof_product->x3);
	element_mul(proof_product->x3,proof_product->challenge,proof_product->x3);
	element_mul(proof_product->x3,proof_product->cp->random_value,proof_product->x3);
}


void su_product_proof_prepare(proof_product_t * proof_product, cl_pk_t * pu_pk,pbc_commitment1_t * cp,pbc_commitment1_t * cf1,pbc_commitment1_t * cf2){
	proof_product->cp=cp;
	proof_product->cf1=cf1;
	proof_product->cf2=cf2;
	proof_product->pairing = pu_pk->pairing;
	//int i;
	//int l = 2;
	element_init_Zr(proof_product->p,pu_pk->pairing);
	element_init_Zr(proof_product->f1,pu_pk->pairing);
	element_init_Zr(proof_product->f2,pu_pk->pairing);
	element_init_Zr(proof_product->challenge,pu_pk->pairing);
	element_init_Zr(proof_product->x1,pu_pk->pairing);
	element_init_Zr(proof_product->x2,pu_pk->pairing);
	element_init_Zr(proof_product->x3,pu_pk->pairing);
	element_init_G1(proof_product->R1,pu_pk->pairing);
	element_init_G1(proof_product->R2,pu_pk->pairing);
	//
	element_set(proof_product->p,cp->value);
	element_set(proof_product->f1,cf1->value);
	element_set(proof_product->f2,cf2->value);
	element_set(proof_product->x1,cf1->hiding_value);
	element_set(proof_product->challenge,cp->challenge);
}
/*
typedef struct {
	cl_signature_t * blinded_sig;
	element_t r;
	element_t rr;
	element_t Vx; //gt
	element_t Vxy; //gt
	element_t * Vxy_i; //gt
	element_t Vs; //gt
} proof_knowledge_signature_t;
	
*/

void su_cl_blind_sig_sign_prepare(proof_knowledge_signature_t * proof, cl_signature_t * blinded_pu_sig, cl_signature_t * pu_sig, pairing_ptr pairing, int message_len, element_t * blinded_A, element_t * blinded_B, element_t * Vxy_i,element_t * miu) {
	//initialize 
	pu_cl_sig_sign_prepare(blinded_pu_sig, pairing, message_len, blinded_A, blinded_B);
	proof->blinded_sig=blinded_pu_sig;
	proof->sig=pu_sig;
	proof->pairing=pairing;
	proof->Vxy_i = Vxy_i;
	proof->miu = miu;
	element_init_Zr(proof->r,pairing);
	element_random(proof->r);
	element_init_Zr(proof->rr,pairing);
	element_random(proof->rr);
	element_init_Zr(proof->p,pairing);
	element_random(proof->p);
	
	element_init_GT(proof->Vx,pairing);
	element_init_GT(proof->Vr,pairing);
	element_init_GT(proof->Vxy,pairing);
	element_init_GT(proof->Vs,pairing);
	int i;
	for(i=0; i<message_len-1;i++){
		element_init_GT(*(proof->Vxy_i+i),pairing);
		element_init_Zr(*(proof->miu+i),pairing);
		element_random(*(proof->miu+i));
	//	element_init_G1(*(proof->blinded_sig->A+i),pairing);
	//	element_init_G1(*(proof->blinded_sig->B+i),pairing);
	//	element_printf("miu  %B\n\n",proof->miu+i);
	}
	element_init_Zr(*(proof->miu+i),pairing);
	element_random(*(proof->miu+i));
	//element_printf("miu  %B\n\n",proof->miu+i);
	// cl_signature_t * pu_sig, pairing_ptr pairing,int message_len, element_t * A,element_t * B
	
	//
}


void su_cl_blind_sig_sign(proof_knowledge_signature_t * proof, cl_pk_t * pu_pk) {
	// blind the signature
	element_pow_zn(proof->blinded_sig->a,proof->sig->a,proof->r);
	element_pow_zn(proof->blinded_sig->b,proof->sig->b,proof->r);
	element_pow_zn(proof->blinded_sig->c,proof->sig->c,proof->r);
	element_pow_zn(proof->blinded_sig->c,proof->blinded_sig->c,proof->rr);
	int i;	
	int l=proof->blinded_sig->len-1;
	pairing_pp_t pp;
	pairing_pp_init(pp,pu_pk->X,pu_pk->pairing);
	// calculate 
	// calculate vx vxy vs
	pairing_pp_apply(proof->Vx,proof->blinded_sig->a,pp);
	pairing_pp_apply(proof->Vxy,proof->blinded_sig->b,pp);
	//paring_pp_apply(proof->Vs,proof->blinded_sig->c,pp);
	pairing_apply(proof->Vs,pu_pk->g,proof->blinded_sig->c,pu_pk->pairing);
	for(i=0;i<l;i++){
		//printf("%d\n\n",i);
	//	element_printf("unblinded  %B\n\n",*(proof->sig->A+i));
		
	//	element_printf("r  %B\n\n",proof->r);
		element_pow_zn(*(proof->blinded_sig->A+i),*(proof->sig->A+i),proof->r);
		element_pow_zn(*(proof->blinded_sig->B+i),*(proof->sig->B+i),proof->r);

		//element_random(*(proof->blinded_sig->A+i));
		//element_random(*(proof->blinded_sig->B+i));
	//	element_printf("blinded  %B\n\n",*(proof->blinded_sig->A+i));
	//	element_printf("blinded  %B\n\n",*(proof->blinded_sig->B+i));
		
		//Vxy_i
		pairing_pp_apply(*(proof->Vxy_i+i),*(proof->blinded_sig->B+i),pp);
	}
	pairing_pp_clear(pp);
	// @TODO this is quite different with Dimitry's implementation.

	// zero-knowledge proof
	element_t Vr_tmp;
	element_init_GT(Vr_tmp,pu_pk->pairing);
	element_pow_zn(Vr_tmp,proof->Vxy,*(proof->miu));
	element_mul(proof->Vr,Vr_tmp,proof->Vx);
	for(i=0;i<l;i++){
		element_pow_zn(Vr_tmp,*(proof->Vxy_i+i),*(proof->miu+i+1));
		element_mul(proof->Vr,Vr_tmp,proof->Vr);
	}
	element_clear(Vr_tmp);
	//end
	

	
}



/*
void _sig_claim_gen(block_ptr block, proof_t proof, inst_t inst, data_ptr claim_secret, data_ptr claim_public) {

	int i; int n = scheme->n; int l = n - 1;
	data_ptr original_sig = inst_supplement(proof, inst, self->sig);
	element_ptr p = get_element(scheme->Z_type, get_part(self->claim_secret_type, claim_secret, 0));
	element_ptr Vq = get_element(scheme->T_type, get_part(self->claim_public_type, claim_public, 0));
	data_ptr blinded_sig_1 = get_part(self->claim_secret_type, claim_secret, 1);
	data_ptr blinded_sig_2 = get_part(self->claim_public_type, claim_public, 1);
	
	data_ptr Zx = get_part(self->claim_secret_type, claim_secret, 2);
	element_ptr r_p = get_element(scheme->Z_type, get_part(self->Zx_type, Zx, 0));
	data_ptr r_message = get_part(self->Zx_type, Zx, 1);
	
	data_ptr Gx = get_part(self->claim_public_type, claim_public, 2);
	element_ptr R_Vs = get_element(scheme->T_type, get_part(self->Gx_type, Gx, 0));
	element_ptr R_Vq = get_element(scheme->T_type, get_part(self->Gx_type, Gx, 1));
	data_ptr R_message = get_part(self->Gx_type, Gx, 2);
	
	// Create a blinded signature by exponentiating all parts of the original signature by q.
	element_t q; element_init(q, scheme->Z_type->field);
	element_random(q);
	for (i = 0; i < 2 * n + 1; i++) {
		element_ptr To = get_element(scheme->G_type, get_item(scheme->sig_type, original_sig, i));
		element_ptr Tb = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, i));
		
		// Tb = To ^ q
		element_pow_zn(Tb, To, q);
	}
	element_clear(q);
	
	// c := c ^ p
	element_ptr c = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, 2));
	element_random(p);
	element_pow_zn(c, c, p);
	copy((type_ptr)scheme->sig_type, blinded_sig_2, blinded_sig_1);
	
	// R_# = g ^ r_# * h ^ o_r_#
	for (i = 0; i < n; i++) {
		element_ptr r = get_element(proof->Z_type, get_item(self->message_type, r_message, i));
		element_ptr o_r = get_element(proof->Z_type, get_item(self->message_type, r_message, n + i));
		element_ptr R = get_element(proof->G_type, get_item(self->message_commitment_type, R_message, i));
		element_random(r);
		element_random(o_r);
		element_pow2_zn(R, proof->g, r, proof->h, o_r);
	}
	
	// Vq = Vx * Vxy ^ m_0 * Vxy_1 ^ m_1 * Vxy_2 ^ m_2 * ...
	// R_Vq = Vxy ^ r_0 * Vxy_1 ^ r_1 * Vxy_2 ^ r_2 * ...
	element_ptr a = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, 0));
	element_ptr b = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, 1));
	element_ptr X = get_element(scheme->G_type, get_item(scheme->public_key_type, self->public_key, 0));
	element_ptr r_0 = get_element(proof->Z_type, get_item(self->message_type, r_message, 0));
	
	pairing_pp_t pp; pairing_pp_init(pp, X, scheme->pairing);
	element_t temp; element_init(temp, scheme->T_type->field);
	element_t temp_R; element_init(temp_R, scheme->T_type->field);
	
	pairing_pp_apply(Vq, a, pp);
	pairing_pp_apply(temp, b, pp);
	element_pow_zn(R_Vq, temp, r_0);
	element_pow_zn(temp, temp, inst->secret_values[self->indices[0]]);
	element_mul(Vq, Vq, temp);
	
	for (i = 0; i < l; i++) {
		element_ptr B = get_element(scheme->G_type, get_item(scheme->sig_type, blinded_sig_1, 3 + (n - 1) + i));
		element_ptr r = get_element(proof->Z_type, get_item(self->message_type, r_message, 1 + i));
		
		pairing_pp_apply(temp, B, pp);
		element_pow_zn(temp_R, temp, r);
		element_mul(R_Vq, R_Vq, temp_R);
		element_pow_zn(temp, temp, inst->secret_values[self->indices[1 + i]]);
		element_mul(Vq, Vq, temp);
	}
	pairing_pp_clear(pp);
	element_clear(temp);
	element_clear(temp_R);
	
	// R_Vs = Vq ^ r_p
	element_random(r_p);
	element_pow_zn(R_Vs, Vq, r_p);
}

*/


// e    	= challenge
// <x, y>	= (bilinear pairing of x and y)
// g     	= scheme->g

// x  	= x in secret key
// y    = y in secret key
// z_#	= z_# in secret key

// X  	= X in public key
// Y  	= Y in public key
// Z_#	= Z_# in public key

// p, q	:: (scheme->Z_type->field)
// a   	= (a in sig) ^ q
// A_# 	= (A_# in sig) ^ q
// b   	= (b in sig) ^ q
// B_# 	= (B_# in sig) ^ q
// c   	= (c in sig) ^ (p * q)

// m_#  	= inst->secret_values[indices[#]]
// o_m_#	= inst->secret_openings[indices[#]]
// C_m_#	= inst->secret_commitments[indices[#]]

// Vx   	= <X, a>	= <g, a> ^ (x * q)
// Vxy  	= <X, b>	= <g, a> ^ (x * y * q)
// Vxy_#	= <X, B_#>	= <g, a> ^ (x * y * z_# * q)
// Vs   	= <g, c>	= (Vx * Vxy ^ m_0 * Vxy_1 ^ m_1 * Vxy_2 ^ m_2 * ...) ^ p

// <Z_#, a>	= <g, A_#>	= <g, a> ^ (z_# * q)
// <Y, a>  	= <g, b>  	= <g, a> ^ (y * q)
// <Y, A_#>	= <g, B_#>	= <g, a> ^ (y * z_# * q)

// Vq	= Vx * Vxy ^ m_0 * Vxy_1 ^ m_1 * Vxy_2 ^ m_2 * ...
// Vs	= Vq ^ p

// [r_p, r_0, o_r_0, r_1, o_r_1, ...]	= (Vq ^ r_p, Vxy ^ r_0 * Vxy_1 ^ r_1 * ..., g ^ r_0 * h ^ o_r_0, g ^ r_1 * h ^ o_r_1, ...)
// [p, m_0, o_m_0, m_1, o_m_1, ...]  	= (Vs, Vq / Vx, C_m_0, C_m_1, ...)




int su_cl_sig_verify(cl_pk_t * pu_pk, cl_sk_t * pu_sk,cl_signature_t * pu_sig, element_t message[]) {
	int i; 
	int l = pu_sig->len - 1;
	
	
	element_t left; element_init_GT(left, pu_pk->pairing);
	element_t right; element_init_GT(right, pu_pk->pairing);
	element_t temp; element_init_GT(temp, pu_pk->pairing);
	
	// Verify <Y, a> = <g, b>
	int result = 1;
	pairing_apply(left, pu_pk->Y, pu_sig->a, pu_pk->pairing);
	pairing_apply(right, pu_pk->g, pu_sig->b, pu_pk->pairing);
	if (element_cmp(left, right)) {
		result = 0;
		goto end;
	}
	
	for (i = 0; i < pu_sig->len-1; i++) {
		
		// Verify <Z, a> = <g, A>
		pairing_apply(left, *(pu_pk->Z+i), pu_sig->a, pu_pk->pairing);
		//element_printf("test %B \n\n",*(pu_pk->Z+i));
		pairing_apply(right, pu_pk->g, *(pu_sig->A+i), pu_pk->pairing);
		if (element_cmp(left, right)) {
			result = 0;
			goto end;
		}
		
		// Verify <Y, A> = <g, B>
		pairing_apply(left, pu_pk->Y, *(pu_sig->A+i), pu_pk->pairing);
		pairing_apply(right, pu_pk->g, *(pu_sig->B+i), pu_pk->pairing);
		if (element_cmp(left, right)) {
			result = 0;
			goto end;
		}
	}
	
	// Verify <X, a> * <X, b> ^ m_0 * <X, B_0> ^ m_1 * <X, B_1> ^ m_2 * ... = <g, c>
	pairing_pp_t pp; pairing_pp_init(pp, pu_pk->X, pu_pk->pairing);
	pairing_pp_apply(left, pu_sig->a, pp);
	pairing_pp_apply(temp, pu_sig->b, pp);
	element_pow_zn(temp, temp, message[0]);
	element_mul(left, left, temp);
	for (i = 0; i < l; i++) {
		pairing_pp_apply(temp, *(pu_sig->B+i), pp);
		element_pow_zn(temp, temp, message[1 + i]);
		element_mul(left, left, temp);
	}
	pairing_pp_clear(pp);
	pairing_apply(right, pu_pk->g, pu_sig->c, pu_pk->pairing);
	result = !element_cmp(left, right);
	
end:


	element_clear(left);
	element_clear(right);
	element_clear(temp);
	
	return result;
}







void su_integer_commit6(integer_commitment_t *c){
	
	// calculate commitment values
	
	// 1 E(v,R) v_commit
	//C
	mpz_t(commit1_tmp1);
	mpz_init(commit1_tmp1);
	mpz_t(commit1_tmp2);
	mpz_init(commit1_tmp2);
	
	mpz_powm (commit1_tmp1, *(c->generator),  *(c->value),  c->n);// g^v mod n
    mpz_powm (commit1_tmp2, *(c->generator+6),  *(c->value+6),  c->n); //h^R mod n
    mpz_mul(c->v_commitment_value,commit1_tmp1,commit1_tmp1);
    mpz_mod(c->v_commitment_value,c->v_commitment_value,c->n);
	
	//Cr
	mpz_powm (commit1_tmp1, *(c->generator),  *(c->random_value),  c->n);// g^rv mod n
    mpz_powm (commit1_tmp2, *(c->generator+6),  *(c->random_value+6),  c->n); //h^Rr mod n
    mpz_mul(c->v_commitment_random_value,commit1_tmp1,commit1_tmp1);
    mpz_mod(c->v_commitment_random_value,c->v_commitment_random_value,c->n);
	
	//free
	mpz_clear(commit1_tmp1);
	mpz_clear(commit1_tmp2);
	/*
    mpz_powm(rightvalue_tmp2,CC_v,e,n);
    mpz_mul(rightvalue_tmp2,rightvalue_tmp2,CC_r);
    mpz_powm_ui(rightvalue_tmp2,rightvalue_tmp2,1,n);
    mpz_set(rightvalue2,rightvalue_tmp2);
	*/
	
	

	
	// 2 e(v,,a,b,d,delta,r) integer_commit
	mpz_t integer_commit6_tmp1;
	mpz_t integer_commit6_tmp2;
//	mpz_t integer_commit6_tmp3;
	mpz_init(integer_commit6_tmp1);
	mpz_init(integer_commit6_tmp2);
//	mpz_init(integer_commit6_tmp3);
	
	//c
	int i;
	mpz_powm (integer_commit6_tmp1,  *(c->generator),  *(c->value),  c->n);
	for(i = 1; i < c->len-1; i++){
		mpz_powm (integer_commit6_tmp2,  *(c->generator+i),  *(c->value+i),  c->n);
	    mpz_mul(integer_commit6_tmp1,integer_commit6_tmp1,integer_commit6_tmp2);
	    mpz_mod(integer_commit6_tmp1,integer_commit6_tmp1,c->n);
	}
	mpz_set(c->integer_commitment_value,integer_commit6_tmp1);
	
	//cr
	mpz_powm (integer_commit6_tmp1,  *(c->generator),  *(c->random_value),  c->n);
	for(i = 1; i < c->len-1; i++){
		mpz_powm (integer_commit6_tmp2,  *(c->generator+i),  *(c->random_value+i),  c->n);
	    mpz_mul(integer_commit6_tmp1,integer_commit6_tmp1,integer_commit6_tmp2);
	    mpz_mod(integer_commit6_tmp1,integer_commit6_tmp1,c->n);
	}
	mpz_set(c->integer_commitment_random_value,integer_commit6_tmp1);
	// free
	mpz_clear(integer_commit6_tmp1);
	mpz_clear(integer_commit6_tmp2);
	
}

void su_integer_commit6_prepare(integer_commitment_t *c, mpz_t *value, mpz_t *random_value, mpz_t *hiding_value, mpz_t *generator,mpz_t v,mpz_t a,mpz_t b,mpz_t d){
	/*
typedef struct  {
-	int len; // 7 0-6
    mpz_t * value;  
    mpz_t * random_value;
	mpz_t * hiding_value;
-	mpz_t challenge;
-   mpz_t * generator;
	// v a b d 4v+1=a^2+b^2+d^2
	mpz_t integer_commitment_value;
	mpz_t integer_commitment_random_value;
	mpz_t integer_commitment_hiding_value_left;
	mpz_t integer_commitment_hiding_value_right;
	// commit v
	mpz_t v_commitment_value;
	mpz_t v_commitment_random_value;
	mpz_t v_commitment_hiding_value_left;
	mpz_t v_commitment_hiding_value_right;
	
} integer_commitment_t; 

	*/
	mpz_init(c->integer_commitment_value);
	mpz_init(c->integer_commitment_random_value);
	mpz_init(c->integer_commitment_hiding_value_left);
	mpz_init(c->integer_commitment_hiding_value_right);
	mpz_init(c->v_commitment_value);
	mpz_init(c->v_commitment_random_value);
	mpz_init(c->v_commitment_hiding_value_left);
	mpz_init(c->v_commitment_hiding_value_right);
	// publish modulo and prime
	
	// parameter for random number generator
	
    mp_bitcnt_t ln = 2048;
    mp_bitcnt_t le = 256;
    mp_bitcnt_t ls = 80;
	mp_bitcnt_t l = le + ls;
    mp_bitcnt_t lr = ln + ls;
	mp_bitcnt_t lrr = lr + le + ls;
	mp_bitcnt_t rand_len[]={l,l,l,l,lr,lrr,lrr};
	// lr+le+ls
	//printf("123");
	// random challenge
	// @TODO generate hash challenge value
	mpz_init(c->challenge);
	mpz_rand_bitlen(c->challenge,le);
	//gmp_printf("hash value %Zd\n\n",(c->challenge));
	// initial
	mpz_init(c->n);
	mpz_init(c->prime1);
	mpz_init(c->prime2);
	publish_modulus(c->n, c->prime1, c->prime2);
	
	// initial
	c->len = 7;
	c->value=value;
	c->random_value=random_value;
	c->hiding_value=hiding_value;
	c->generator=generator;
	//gmp_printf("before %Zd\n\n",c->value+1);
	int i;
	for(i = 0; i < c->len; i++)
	{	
		mpz_init(*(c->value+i));
		//gmp_printf("after %Zd\n\n",*(c->value+i));
		//mpz_init(c->value[i]);
		mpz_init(*(c->random_value+i));
		mpz_init(*(c->hiding_value+i));
		mpz_init(*(c->generator+i));

		if (i!=6) {
			get_random_qr_n(*(c->generator+i),c->prime1, c->prime2,c->n);			
		} else
			mpz_set(*(c->generator+i),*(c->generator+i-1));
		// gmp_printf("generator %d %Zd\n\n",i,*(c->generator+i));
		mpz_rand_bitlen(*(c->random_value+i),rand_len[i]); // random value
		
		
		// calculate hiding value
		//gmp_printf("random value %d %Zd\n\n",i,*(c->random_value+i));
	}
//	gmp_printf("after %Zd\n\n",c->value+1);
//	mpz_set_si(c->value+1,123);
//	gmp_printf("after %Zd\n\n",c->value+1);
	//gmp_printf("generator %Zd\n\n",c->generator+1);
	
	mpz_set(*(c->value),v);
	mpz_set(*(c->value+1),a);
	mpz_set(*(c->value+2),b);
	mpz_set(*(c->value+3),d);
	// r & R
	mpz_rand_bitlen(*(c->value+5),lr); 
	mpz_rand_bitlen(*(c->value+6),lr); 

	
	// delta
    // delta = 4*r_v
	mpz_t delta;
	mpz_init(delta);
	mpz_t delta_tmp;
	mpz_init(delta_tmp);
    mpz_mul_ui(delta,*(c->random_value),4);
    //delta = 4*r_v-2*a*r_a
    mpz_mul(delta_tmp,*(c->value+1),*(c->random_value+1));
    mpz_submul_ui(delta,delta_tmp,2); 
    //delta = 4*r_v-2*a*r_a-2*b*r_b
    mpz_mul(delta_tmp,*(c->value+2),*(c->random_value+2));
    mpz_submul_ui(delta,delta_tmp,2); 
    //delta = 4*r_v-2*a*r_a-2*b*r_b-2*d*r_d
    mpz_mul(delta_tmp,*(c->value+3),*(c->random_value+3));
    mpz_submul_ui(delta,delta_tmp,2);
    mpz_set(*(c->value+4),delta);
	// r_delta = - ra^2 -rb^2 -rc^2
    mpz_pow_ui(delta_tmp,*(c->random_value+1),2);
    mpz_neg(delta,delta_tmp);
    mpz_submul(delta,*(c->random_value+2),*(c->random_value+2));
    mpz_submul(delta,*(c->random_value+3),*(c->random_value+3));
	mpz_set(*(c->random_value+4),delta);
	//free
	mpz_clear(delta_tmp);
	mpz_clear(delta);
	
	mpz_t deltah_tmp; mpz_init(deltah_tmp);
	// calculate hiding value
	for(i = 0; i < c->len; i++) {
		if (i!=4) {
			mpz_set(*(c->hiding_value+i), *(c->random_value+i));
			mpz_addmul (*(c->hiding_value+i ), c->challenge, *(c->value+i));
		} else {
			// calculate special hiding_delta
		    mpz_set(deltah_tmp,c->challenge);
		    mpz_addmul_ui(deltah_tmp,*(c->hiding_value),4);
		    mpz_mul(deltah_tmp,deltah_tmp,c->challenge);
		    mpz_submul(deltah_tmp,*(c->hiding_value+1),*(c->hiding_value+1));
		    mpz_submul(deltah_tmp,*(c->hiding_value+2),*(c->hiding_value+2));
		    mpz_submul(deltah_tmp,*(c->hiding_value+3),*(c->hiding_value+3));
		    mpz_set(*(c->hiding_value+i),deltah_tmp);
		}

	}
	mpz_clear(deltah_tmp);
		
	
}

void su_pbc_commit1_prepare(pbc_commitment1_t *c, pairing_ptr pairing, element_t value){
	
	c->pairing = pairing;
    element_init_Zr(c->value,pairing);
    element_init_Zr(c->random_value,pairing);
    element_init_Zr(c->opening_value,pairing);
    element_init_Zr(c->random_opening_value,pairing);
    element_init_Zr(c->hiding_value,pairing);
	element_init_Zr(c->hiding_opening_value,pairing);
    element_init_Zr(c->challenge,pairing);
    element_init_G1(c->commitment_value,pairing);
    element_init_G1(c->commitment_random_value,pairing);
    element_init_G1(c->commitment_hiding_value_left,pairing);
	element_init_G1(c->commitment_hiding_value_right,pairing);
    element_init_G1(c->g,pairing);
    element_init_G1(c->h,pairing);
	// random
  //  element_random(c->value);
    element_set(c->value,value);
	element_random(c->random_value);
    element_random(c->opening_value);
    element_random(c->random_opening_value);
    element_random(c->challenge); // random challenge, test for real challenge generator later
   
	// set hiding value xh = x*e + xr
	element_mul(c->hiding_value,c->challenge,c->value);
	element_add(c->hiding_value,c->hiding_value,c->random_value);
	element_mul(c->hiding_opening_value,c->challenge,c->opening_value);
	element_add(c->hiding_opening_value,c->hiding_opening_value,c->random_opening_value);
	
	
   
    element_random(c->g);
    element_random(c->h);
	/*
 	element_printf("Publishing  value : %B \n\n",c->value);
 	element_printf("Publishing random value : %B \n\n",c->random_value);
  	element_printf("Publishing opening value : %B \n\n",c->opening_value);
  	element_printf("Publishing random opening value : %B \n\n",c->random_opening_value);
  	element_printf("Publishing g  value : %B \n\n",c->g);
  	element_printf("Publishing h  value : %B \n\n",c->h);
	*/
}

void decompose_prime(mpz_t a, mpz_t b, mpz_t p){
    mpz_t x0; mpz_init(x0);
    mpz_t x1; mpz_init(x1);
    mpz_t r1; mpz_init(r1);
    mpz_t r; mpz_init(r);
    // Cornacchia's algorithm
    // Step 1:
    modular_square_root(x0, p);
    mpz_sub(x1,p,x0);
    if (mpz_cmp(x1,x0) >0 ) {
        mpz_set(x0,x1);
    }
    
    // Step 2:
    
    mpz_mod(r1,p,x0);
    mpz_t rs; mpz_init(rs);    
    mpz_pow_ui(rs,r1,2L);
    while (mpz_cmp(rs,p) >0 ) { 
          mpz_mod(r,x0,r1);
          mpz_set(x0,r1);
          mpz_set(r1,r);
          mpz_pow_ui(rs,r,2L);
    }      

    // Step 3:
    mpz_init_set(a,r1);
    mpz_pow_ui(r,r1,2L);
    mpz_sub(r,p,r);
    mpz_sqrt(r,r);
    mpz_init_set(b,r);
    mpz_clear(x0); 
    mpz_clear(x1);
    mpz_clear(r1);
    mpz_clear(r);
}

void decomose_twoprimes(mpz_t a, mpz_t x, mpz_t y, mpz_t p){
      mpz_t c; mpz_init(c);
      mpz_t r; mpz_init(r);
      mpz_t q; mpz_init(q);
      mpz_t t; mpz_init(t);
      mpz_t p1; mpz_init(p1);

      mpz_set_ui(a, 0L);

      int flag=0;
      int reps=5;
      int ip=5;
      int i=0; // x or y is composite if i=1.
      
      while (flag==0) {   //should randomly choose a
          mpz_set_ui(x, 1L);
          mpz_pow_ui(c,a,2L); //c=a^2
          mpz_sub(p1,p,c);    //p=p-a^2
          mpz_sqrt(r,p1);
          i=0;
          while (mpz_cmp(r,x) >=0 && flag==0 && i==0){ 
        //  while (mpz_cmp(r,x) >=0 && flag==0){ 
               mpz_fdiv_qr(y, t, p1, x);
               if (!mpz_cmp_ui(t,0L)) {
                     mpz_mod_ui(t,y,4);
                     if (!mpz_cmp_ui(t,1L)) {
                          ip=mpz_probab_prime_p(x, reps);
                          if (!mpz_cmp_ui(x,1L)) {ip=2;}
                          if (ip==2) {
                              ip=mpz_probab_prime_p(y, reps);
                              if (!mpz_cmp_ui(y,1L)) {ip=2;}
                              if (ip==2) {
                                    flag=1;
                              }
                              else {
                                    i=1;
                                    if (!mpz_cmp_ui(x,1L)) {i=0;}
                              }
                          }
                          else{
                              i=1;
                          }
                     }      
               }
               mpz_add_ui(x,x,4L);
          }
          mpz_add_ui(a,a,2L);
      }
      mpz_sub_ui(x,x,4L);
      mpz_sub_ui(a,a,2L);
      

      mpz_clear(c);
      mpz_clear(r);
      mpz_clear(q);
      mpz_clear(t);
      mpz_clear(p1);

}

void modular_square_root(mpz_t x0,mpz_t p){
      //Tonelli-shanks algorithm (wiki)
      mpz_t b; mpz_init(b);
      mpz_t c; mpz_init(c);
      mpz_t r; mpz_init(r);
      mpz_t q; mpz_init(q);
      long int s;
      mpz_t z; mpz_init(z);
      mpz_t n; mpz_init(n);
      long int m;
      mpz_t t; mpz_init(t);
      mpz_t pmin1; mpz_init(pmin1);
      mpz_t tmp; mpz_init(tmp);
      long int i=1;    
	  
	  if(mpz_cmp_ui(p,1L)==0) {
		  mpz_set(x0,p);
	  } else {
		  mpz_sub_ui(pmin1,p,1L);
      	  mpz_sub_ui(c,p,1L); // c=p-1
      	  mpz_fdiv_qr_ui(q, r, c, 2L); // c=2*q+r
      	  while (mpz_cmp_ui(r,0L) ==0) {
        	   i=i+1;
          	   mpz_set(c,q);
           	   mpz_fdiv_qr_ui(q, r, c, 2L);
		   }
      	 mpz_mul_ui(q,q,2L);
      	 mpz_add_ui(q,q,1L);
      	 s=i-1; // end of step 1

      	 mpz_set_ui(z,2L); //z=2
      	 mpz_sub_ui(tmp,p,1L); // tmp=p-1
      	 mpz_fdiv_q_ui(tmp,tmp,2L); //tmp=(p-1)/2
      	 mpz_powm(c,z,tmp,p); //
      while (mpz_cmp(c,pmin1) !=0) {
           mpz_add_ui(z,z,1L);
           mpz_powm(c,z,tmp,p);
      }
      mpz_powm(c,z,q,p); // end of step 2
      
      mpz_set(n,pmin1);
      //mpz_set_ui(n,10L);
      mpz_add_ui(tmp,q,1L); //tmp=q+1
      mpz_fdiv_q_ui(tmp,tmp,2L); //tmp=(q+1)/2
      mpz_powm(x0,n,tmp,p); //x0=n^tmp mod (p)
      mpz_powm(t,n,q,p); // t=n^q mod (p)
      m=s;  //end of step 3

      while (mpz_cmp_ui(t,1L) !=0) {
           i=1;
           mpz_ui_pow_ui(tmp,2,i); // tmp=2^i
           mpz_powm(tmp,t,tmp,p); // tmp=t^(2^i) mod p
          while (mpz_cmp_ui(tmp,1L) !=0 && i < m ){
                i=i+1;
                mpz_set_ui(tmp,2*i);
                mpz_powm(tmp,t,tmp,p);
           } 
           
           mpz_ui_pow_ui(tmp,2,m-(i+1));
           mpz_powm(b,c,tmp,p);
           mpz_mul(x0,x0,b);    
           mpz_mod(x0,x0,p);
           mpz_mul(c,b,b);
           mpz_mod(c,c,p);
           mpz_mul(t,t,c);
           mpz_mod(t,t,p);
           m=i;
      }    //end of step 4

      mpz_clear(b);
      mpz_clear(c);
      mpz_clear(r);
      mpz_clear(q);
      mpz_clear(z);
      mpz_clear(n);
      mpz_clear(t);
      mpz_clear(tmp);
      mpz_clear(pmin1);
}
}

void sum_of_squares(mpz_t a, mpz_t b, mpz_t d, mpz_t p){
    mpz_t x; mpz_init(x);
    mpz_t y; mpz_init(y);

    decomose_twoprimes(a, x, y, p);
    mpz_t a0; mpz_init(a0);
    mpz_t b0; mpz_init(b0);
    mpz_t c0; mpz_init(c0);
    mpz_t d0; mpz_init(d0);

    decompose_prime(a0, b0, x);
    decompose_prime(c0, d0, y);

	//b=a0*c0+b0*d0
	mpz_mul(x,a0,c0);
    //gmp_printf("%Zd\n\n",x);
	mpz_mul(y,b0,d0);
    //gmp_printf("%Zd\n\n",y);
	mpz_add(b,x,y);
    //gmp_printf("%Zd\n\n",b);

	//d=|a0*d0+b0*c0|
	mpz_mul(x,a0,d0);
	mpz_mul(y,b0,c0);
	mpz_sub(d,x,y);
	mpz_abs(d,d);
    
    mpz_clear(a0); 
    mpz_clear(b0);
    mpz_clear(c0);
    mpz_clear(d0);
    mpz_clear(x);
    mpz_clear(y);
}
