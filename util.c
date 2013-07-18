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


void get_cl_commitment(cl_pk_t * pu_pk, element_t message[],element_t commitment){
	int i;
	int l= pu_pk->len-1;

	element_t temp; element_init_G1(temp, pu_pk->pairing);
	

	element_pow_zn(commitment, pu_pk->g, message[0]);

	for (i = 0; i < l; i++) {
		element_pow_zn(temp, *(pu_pk->Z+i), message[1 + i]);
		element_mul(commitment, commitment, temp);
	}
	element_clear(temp);
}


void mpz_rand_bitlen(mpz_t rand_num,unsigned long int bitlen)
{
	
    // random setting
    mpz_t randtmp; mpz_init(randtmp);
	mpz_t rndseed; mpz_init(rndseed);
    gmp_randstate_t state;  
	   
    //@TODO need better random scheme
    //gmp_randinit_lc_2exp_size(state, 128); 
	gmp_randinit_mt (state);
	
	
    setrndseed(rndseed);
    gmp_randseed(state,rndseed);
    //mpz_rrandomb(randtmp, state, bitlen);
    mpz_urandomb(randtmp, state, bitlen);
	mpz_set(rand_num,randtmp);
	mpz_clear(randtmp);
	mpz_clear(rndseed);
	gmp_randclear(state);
}


void get_element_rand_zn(mpz_t element, mpz_t n) {
	//get an element from Zp
	// all element should be initialed.
  	gmp_randstate_t state;
  	mpz_t rndseed; mpz_init(rndseed);

  	//gmp_randinit_lc_2exp_size(state,128);
  	gmp_randinit_mt (state);
  	setrndseed(rndseed);

  	gmp_randseed(state, rndseed);

  	//@TODO is urandomm ok??
  	mpz_urandomm(element,state,n);
	//gmp_printf("random %Zd\n\n",n);
	//gmp_printf("random %Zd\n\n",element);
	gmp_randclear(state);
  	mpz_clear(rndseed);
}


// random get QR_n
void get_random_qr_n(mpz_t qr_generator,mpz_t prime1, mpz_t prime2, mpz_t n) {


    mpz_t qr_tmp; mpz_init(qr_tmp);

    while(1) {
      get_element_rand_zn(qr_tmp,n);

      if ( (mpz_divisible_p(qr_tmp, prime1) == 0) && (mpz_divisible_p(qr_tmp, prime2) == 0) ) break;
    }

    // square and mod n
    mpz_powm_ui (qr_generator, qr_tmp, 2, n);
   
    // free
    mpz_clear(qr_tmp);

}




//@TODO put those functions to correct pu.c or su.c
void pbc_commit1(pbc_commitment1_t *c){
	
	/*
  	element_printf("Publishing  value : %B \n\n",c.value);
  	element_printf("Publishing random value : %B \n\n",c.random_value);
  	element_printf("Publishing opening value : %B \n\n",c.opening_value);
  	element_printf("Publishing random opening value : %B \n\n",c.random_opening_value);
  	element_printf("Publishing g  value : %B \n\n",c.g);
  	element_printf("Publishing h  value : %B \n\n",c.h);
	*/
	
	// C-x C-xr
	element_pow2_zn(c->commitment_value,c->g,c->value,c->h,c->opening_value);
	//element_printf("Publishing commitment value : %B \n\n",c.commitment_value);
	element_pow2_zn(c->commitment_random_value,c->g,c->random_value,c->h,c->random_opening_value);
	//element_printf("Publishing commitment value : %B \n\n",c.commitment_random_value);
}


void sha256(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}



// @SEE https://github.com/zz3599/RSA/blob/master/rsaengine.c
// credit to zz3599@github
void randomPrime(mpz_t prime, int length){
	
	gmp_randstate_t state;
	gmp_randinit_default (state);
	gmp_randseed_ui(state, time(0));
	//make sure generated prime is has exactly (length) number of digits
	mpz_t max, min;
	mpz_init(max);  mpz_init(min);
	mpz_ui_pow_ui(max, 2, length);
	mpz_ui_pow_ui(min, 2, length-1);
  
	mpz_t random;
	mpz_init(random);
	mpz_urandomm(random, state, max);
	while(mpz_cmp(random, min) < 0){
		mpz_urandomm(random, state, max);
	}
	//gets first prime greater than random
	mpz_nextprime(prime, random);
	mpz_clear(max);
	mpz_clear(min);
	mpz_clear(random);
	gmp_randclear(state);
	
	
	/*
	mpz_urandomb (p, rs, n/2);
	mpz_setbit (p, n / 2 - 1);
	mpz_setbit (p, n / 2 - 2);
	mpz_nextprime (p, p);

	mpz_urandomb (q, rs, n/2);
	mpz_setbit (q, n / 2 - 1);
	mpz_setbit (q, n / 2 - 2);
	mpz_nextprime (q, q);
	*/
}

void publish_modulus(mpz_t n, mpz_t prime1, mpz_t prime2) {

  mpz_t rand1, tmpprime, tmp, rndseed;
  gmp_randstate_t state;

  mpz_init(rand1); mpz_init(tmpprime); mpz_init(tmp); mpz_init(rndseed);


  //gmp_randinit_lc_2exp_size(state, 128); 
  gmp_randinit_mt (state);

  /* computes 1st prime */
  setrndseed(rndseed);

  // 4r+3 except 5
  // 2p+1 p is prime
  gmp_randseed(state, rndseed);
  //mpz_rrandomb(rand, state, 1024);
  mpz_urandomb(rand1, state, 1024);
  while (1) {                          /* repeat until prime is of form 4r+3 which is a safe prime*/
    mpz_nextprime(tmpprime, rand1);     
    mpz_sub_ui(tmp, tmpprime, 3);
    if (mpz_divisible_ui_p(tmp, 4)) break;
    mpz_set(rand1, tmpprime);
  } 
  mpz_set(prime1, tmpprime);

  /* computes 2nd prime */
  setrndseed(rndseed);
  gmp_randseed(state, rndseed);
  //mpz_rrandomb(rand, state, 1024);
  mpz_urandomb(rand1, state, 1024);
  while (1) {                    
    mpz_nextprime(tmpprime, rand1);     
    mpz_sub_ui(tmp, tmpprime, 3);
    if (mpz_divisible_ui_p(tmp, 4)) break;
    mpz_set(rand1, tmpprime);
  } 
  mpz_set(prime2, tmpprime);

  /* computes modulus */
  mpz_mul(n, prime1, prime2);
  /*
  if (debug_option_p) {
	  gmp_printf("Publishing modulus n(%zd bit): %Zd \n\n", mpz_sizeinbase(n,2),n);
	  gmp_printf("Publishing prime1 p(%zd bit): %Zd\n\n", mpz_sizeinbase(prime1,2),prime1);
	  gmp_printf("Publishing prime2 q(%zd bit): %Zd\n\n", mpz_sizeinbase(prime2,2),prime2);
  }
  */
  mpz_clear(rand1);
  mpz_clear(tmpprime);
  mpz_clear(tmp);
  mpz_clear(rndseed);
  gmp_randclear(state);
}

void setrndseed(mpz_t rndseed)
{
    FILE *rnd;
    mpz_t rndtmp;
    unsigned long int idx;


     mpz_init(rndtmp);

    rnd = fopen("/dev/urandom","r"); //must run in a linux machine

    //@TODO better seeding methods

    
    for ( idx=0 ; idx < 128 ; idx++ ) {
        mpz_set_ui(rndtmp, (unsigned long int) getc(rnd));
        mpz_mul_2exp(rndtmp, rndtmp, idx*8); // not clear left shift from github ajduncan/nzkp
        mpz_add(rndseed,rndseed,rndtmp);
        }
    fclose(rnd);
    mpz_clear(rndtmp);
    
}
