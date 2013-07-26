#ifndef UTIL_H_
#define UTIL_H_


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


//@TODO need adjustment here!!
typedef struct  {
	int len; // 7 0-6
	mpz_t prime1;
	mpz_t prime2;
	mpz_t n;
    mpz_t * value;
	//mpz_t * opening_value;
    mpz_t * random_value;
	//mpz_t random_opening_value;
	mpz_t * hiding_value;
	mpz_t challenge;
    mpz_t * generator;
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


typedef struct  {
	element_t a;
	element_t * A;
	element_t b;
	element_t * B;
	element_t c;
	int len;	
} cl_signature_t; 

typedef struct {
	pairing_ptr pairing;
	cl_signature_t * sig;
	cl_signature_t * blinded_sig;
	element_t r;
	element_t rr;
	element_t p;
	element_t Vx; //gt
	element_t Vxy; //gt
	element_t * Vxy_i; //gt
	element_t Vs; //gt
	element_t * miu;
	element_t Vr; //R_Vq 
} proof_knowledge_signature_t;

/*
typedef struct {
	pairing_ptr pairing;
	element_t p;
	element_t f1;
	element_t f2;
//	element_t R1;
//	element_t R2;
	element_t D1; // f1的hiding value
	element_t D2; // d1 d2 d3
	element_t D3;
	element_t u1;
	element_t u2;
	element_t v1;
	element_t v2;
	element_t v3;
	element_t challenge;
	pbc_commitment1_t * cp;
	pbc_commitment1_t * cf1;
	pbc_commitment1_t * cf2;
	int len;
} proof_product_t;
*/

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
	element_t r1;
	element_t r2;
	element_t r3;
	element_t challenge;
	pbc_commitment1_t * cp;
	pbc_commitment1_t * cf1;
	pbc_commitment1_t * cf2;
	int len;
} proof_product_t;

typedef struct  {
	pairing_ptr pairing;
	element_t g;
	element_t X;
	element_t Y;
	element_t *Z;
	int len;
} cl_pk_t; 

typedef struct  {
	element_t x;
	element_t y;
	element_t * z;
	int len;
} cl_sk_t; 



/*
unsigned num_elements = 1000;
mpz_t * my_array;
my_array = malloc(sizeof(mpz_t) * num_elements);
//Initalize
//Use
//Clear
free(my_array);
*/

void pbc_commit1(pbc_commitment1_t *c);
void integer_commit6(integer_commitment_t c,mpz_t n);
void randomPrime(mpz_t prime, int length);
void publish_modulus(mpz_t n, mpz_t prime1, mpz_t prime2);//get same prime
void setrndseed(mpz_t rndseed);
void get_random_qr_n(mpz_t qr_generator,mpz_t prime1, mpz_t prime2, mpz_t n);
void get_element_rand_zn(mpz_t element, mpz_t n);
void mpz_rand_bitlen(mpz_t rand_num,unsigned long int bitlen);
void get_cl_commitment(cl_pk_t * pu_pk, element_t message[],element_t commitment);
void sha256(char *string, char outputBuffer[65]);


/* decomposite a value to the sum of three squares */
void decompose_prime(mpz_t a, mpz_t b, mpz_t p);
void decomose_twoprimes(mpz_t a,mpz_t x, mpz_t y, mpz_t p);
void modular_square_root(mpz_t x0,mpz_t p);
void sum_of_squares(mpz_t a, mpz_t b, mpz_t d, mpz_t p);


// pbc commit
void su_pbc_commit1_prepare(pbc_commitment1_t *c, pairing_ptr pairing, element_t value);
// integer commit
void su_integer_commit6_prepare(integer_commitment_t *c, mpz_t *value, mpz_t *random_value, mpz_t *hiding_value, mpz_t *generator,mpz_t v,mpz_t a,mpz_t b,mpz_t d, mpz_t n, mpz_t prime1, mpz_t prime2);
void su_integer_commit6(integer_commitment_t *c);
int su_cl_sig_verify(cl_pk_t *pu_pk, cl_sk_t *pu_sk,cl_signature_t *pu_sig, element_t message[]);
void su_cl_blind_sig_sign_prepare(proof_knowledge_signature_t * proof, cl_signature_t * blinded_pu_sig, cl_signature_t * pu_sig, pairing_ptr pairing, int message_len, element_t * blinded_A, element_t * blinded_B, element_t * Vxy_i,element_t * miu);
void su_cl_blind_sig_sign(proof_knowledge_signature_t * proof, cl_pk_t * pu_pk);
void su_product_proof_prepare(proof_product_t * proof_product, cl_pk_t * pu_pk,pbc_commitment1_t * cp,pbc_commitment1_t * cf1,pbc_commitment1_t * cf2);
void su_product_proof(proof_product_t * proof_product);




int pu_pbc_commit1_verify(pbc_commitment1_t c);
int pu_integer_commit6_verify(integer_commitment_t *c);
void pu_cl_key_gen (cl_pk_t * pu_pk, cl_sk_t * pu_sk, element_t * message,int message_len, pairing_ptr pairing, element_t * z, element_t * Z);
void pu_cl_sig_sign_prepare(cl_signature_t * pu_sig, pairing_ptr pairing,int message_len, element_t * A,element_t * B);
void pu_cl_sig_sign(cl_pk_t * pu_pk, cl_sk_t * pu_sk,cl_signature_t * pu_sig, element_t message[],int message_len);
int pu_cl_blind_sig_verify(proof_knowledge_signature_t * proof, cl_pk_t * pu_pk);
int pu_product_proof_verify(proof_product_t * proof_product);
int pu_sum_fee_verify(pbc_commitment1_t * c_fee1,pbc_commitment1_t * c_fee2,pbc_commitment1_t * sum_fee);
#endif







