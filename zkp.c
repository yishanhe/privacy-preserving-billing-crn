#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h> //using to get HASH for NIKP
#include <pbc/pbc.h>

#define TRUE 1
#define FALSE 0

int fastseed = FALSE; //make it work in mac if setting to TRUE

typedef struct  {
    mpz_t v;
    mpz_t a;
    mpz_t b;
    mpz_t d;
    mpz_t delta;
    mpz_t r;
} commitment_t; 

// declare
void setrndseed();
void publish_modulus();
void get_element_rand_zn(mpz_t element);
void get_qr_n(mpz_t qr_generator);
void get_commitment(mpz_t commitment_value,commitment_t cm);
void sha256(char *string, char outputBuffer[65]);
void timestamp(FILE *out);



// public variables
mpz_t n; //modulus
mpz_t prime1;
mpz_t prime2;
mpz_t rndseed;
commitment_t c,cr;
commitment_t qr;
commitment_t ch;

int main(int argc, const char *argv[])
{
    // define the length
  // mp_bitcnt_t typdef
    unsigned long ln = 2048;
    unsigned long le = 256;
    unsigned long ls = 80;
    unsigned long lr = ln + ls;


    /* for random setting */
    mpz_t randtmp; mpz_init(randtmp);
    mpz_init(rndseed);
    // random choose r_*
    gmp_randstate_t state;     
    //@TODO need better random scheme
    gmp_randinit_lc_2exp_size(state, 128); 




    // publis modulo and prime1 and prime2
    publish_modulus();  // n and two safe primes: prime1 prime2 are initialized in there.



    // initial structs 

    mpz_init(c.v); mpz_init(c.a); mpz_init(c.b); mpz_init(c.d); mpz_init(c.r); mpz_init(c.delta);
    mpz_init(cr.v); mpz_init(cr.a); mpz_init(cr.b); mpz_init(cr.d); mpz_init(cr.r); mpz_init(cr.delta);
    mpz_init(qr.v); mpz_init(qr.a); mpz_init(qr.b); mpz_init(qr.d); mpz_init(qr.r); mpz_init(qr.delta);
   


    // manually assign value to v a b d
    // 4v+1 = a^2 + b^2 + d^2
    // a=2 b=3 d=6, v= 12
    mpz_set_ui(c.v,12);
    gmp_printf("Publishing v value: %Zd\n\n", c.v);
    mpz_set_ui(c.a,2);
    mpz_set_ui(c.b,3);
    mpz_set_ui(c.d,6);

	// random number
    setrndseed();
    gmp_randseed(state,rndseed);
    mpz_rrandomb(randtmp, state, lr);
    mpz_set(c.r,randtmp);
    gmp_printf("Publishing r value: %Zd\n\n", c.r);


	// random number for cr
    setrndseed();

    gmp_randseed(state,rndseed);

    // here 128 is chosen arbitrarily 
    // @TODO need to determine the size in the future
    mpz_rrandomb(randtmp, state, le + ls);
    mpz_set(cr.v,randtmp);
    gmp_printf("Publishing random v value: %Zd\n\n", cr.v);

    setrndseed();
    gmp_randseed(state,rndseed);
    mpz_rrandomb(randtmp, state, le + ls);
    mpz_set(cr.a,randtmp);

    setrndseed();
    gmp_randseed(state,rndseed);
    mpz_rrandomb(randtmp, state, le + ls);
    mpz_set(cr.b,randtmp);

    setrndseed();
    gmp_randseed(state,rndseed);
    mpz_rrandomb(randtmp, state, le + ls);
    mpz_set(cr.d,randtmp);

    setrndseed();
    gmp_randseed(state,rndseed);
    mpz_rrandomb(randtmp, state, lr +  le + ls);
    mpz_set(cr.r,randtmp);
    gmp_printf("Publishing random r value: %Zd\n\n", cr.r);



    
    // free
    mpz_clear(randtmp);

    // generator must be QR
    // power it up and mod
    get_qr_n(qr.v); gmp_printf("Publishing g1: %Zd\n\n", qr.v);
    get_qr_n(qr.a); gmp_printf("Publishing g2: %Zd\n\n", qr.a);
    get_qr_n(qr.b); gmp_printf("Publishing g3: %Zd\n\n", qr.b);
    get_qr_n(qr.d); gmp_printf("Publishing g4: %Zd\n\n", qr.d);
    get_qr_n(qr.r); gmp_printf("Publishing g5: %Zd\n\n", qr.r);
    get_qr_n(qr.delta); gmp_printf("Publishing h: %Zd\n\n", qr.delta);


    



    //calculate delta
    // delta = 4*r_v
    mpz_t delta; mpz_init(delta);
    mpz_mul_ui(delta,cr.v,4);
    mpz_t delta_tmp; mpz_init(delta_tmp);
    
    //delta = 4*r_v-2*a*r_a
    mpz_mul(delta_tmp,c.a,cr.a);
    mpz_submul_ui(delta,delta_tmp,2);
    
    //delta = 4*r_v-2*a*r_a-2*b*r_b
    mpz_mul(delta_tmp,c.b,cr.b);
    mpz_submul_ui(delta,delta_tmp,2);
    
    //delta = 4*r_v-2*a*r_a-2*b*r_b-2*d*r_d
    mpz_mul(delta_tmp,c.d,cr.d);
    mpz_submul_ui(delta,delta_tmp,2);

    mpz_set(c.delta,delta);

    //calculate cr.delta
    mpz_pow_ui(delta_tmp,cr.a,2);
    mpz_neg(cr.delta,delta_tmp);
    mpz_submul(cr.delta,cr.b,cr.b);
    mpz_submul(cr.delta,cr.d,cr.d);


    // free
    mpz_clear(delta_tmp);







    // commitment
    mpz_t c_value; mpz_init(c_value);
    get_commitment(c_value,c);
    gmp_printf("Publishing commitment c value: %Zd\n\n", c_value);
    mpz_t cr_value; mpz_init(cr_value);
    get_commitment(cr_value,cr);
    gmp_printf("Publishing commitment cr value: %Zd\n\n", cr_value);
    

    // challenge
    // shoud be hash
    mpz_t e; mpz_init(e);
    mpz_set_ui(e,3);
    gmp_printf("Publishing artificial hash challenge value e: %Zd\n\n", e);

    // SHA1(INPUT, strlen(INPUT),output)
    // input is char input[]
    //output unsigned char output[]
    // int mpz_set_str (mpz_t rop, char *str, int base)
    // char * mpz_get_str (char *str, int base, mpz_t op)

    // in order to use sha256 for cr1 and cr2
    char * char_cr = mpz_get_str (NULL, 10, cr_value);
    char * char_c = mpz_get_str (NULL, 10, c_value);
	
    printf("The string char_cr is %s \n\n", char_cr);
	printf("char_cr length is %zd \n\n",strlen(char_cr));
    printf("The string char_c is %s \n\n", char_c);
	printf("char_c length is %zd \n\n",strlen(char_c));

    // c left shift then cat cr
    size_t c_value_len =  mpz_sizeinbase(c_value,2);
    printf("%zd\n", c_value_len);
    size_t n_len =  mpz_sizeinbase(n,2);
    printf("The length of modulo: %zd\n", n_len);
	
	// cat char_cr & char_c
    char * dest = (char *)malloc((strlen(char_cr)+strlen(char_c)+1)*sizeof(char));
	strcat(dest,char_cr); 
	strcat(dest,char_c); 

    printf("The string dest is %s \n\n", dest);
	printf("The new dest length is %zd \n\n", strlen(dest));
/* 
    mpz_t c_value_hash_tmp; mpz_init(c_value_hash_tmp);
    mpz_mul_2exp(c_value_hash_tmp,c_value,c_value_len);
    mpz_t value_to_hash_tmp; mpz_init(value_to_hash_tmp);
    mpz_add(value_to_hash_tmp,c_value_hash_tmp,cr_value);
    size_t value_to_hash_tmp_len =  mpz_sizeinbase(value_to_hash_tmp,2);
    printf("%zd\n", value_to_hash_tmp_len);
    
    
    gmp_printf("Publishing value to hash tmp: %Zd\n\n", value_to_hash_tmp);
    // do free here
 */


    //static unsigned char buffer[65];
    static char buffer[65];
    sha256(dest, buffer);
    printf("THE SHA256 result is %s\n\n", buffer);
	
	// change this hex char in to mpz type
	mpz_t e_sha256; mpz_init(e_sha256);
	if (mpz_set_str (e_sha256, buffer, 16)==0){
        gmp_printf("Publishing SHA256 challenge value e: %Zd\n\n", e_sha256);
	    mpz_set(e,e_sha256);
    }
    else{
        printf("Generate SHA256 failed, using artificial e instead! \n\n");
    }
	


    // hiding value
    mpz_init_set(ch.v,cr.v); mpz_init_set(ch.a,cr.a); mpz_init_set(ch.b,cr.b); mpz_init_set(ch.d,cr.d); mpz_init_set(ch.r,cr.r); mpz_init_set(ch.delta,cr.delta);
    
    
    // vh
    mpz_addmul (ch.v, e, c.v);
    gmp_printf("Publishing v-hiding value: %Zd\n\n", ch.v);
    // ah
    mpz_addmul (ch.a, e, c.a);
    gmp_printf("Publishing a-hiding value: %Zd\n\n", ch.a);
    // bh
    mpz_addmul (ch.b, e, c.b);
    gmp_printf("Publishing b-hiding value: %Zd\n\n", ch.b);
    // dh
    mpz_addmul (ch.d, e, c.d);
    gmp_printf("Publishing d-hiding value: %Zd\n\n", ch.d);
    // rh
    mpz_addmul (ch.r, e, c.r);
    gmp_printf("Publishing r-hiding value: %Zd\n\n", ch.r);
    
    // deltah get delta of hiding value
    mpz_t deltah_tmp; mpz_init(deltah_tmp);
    mpz_set(deltah_tmp,e);
    mpz_addmul_ui(deltah_tmp,ch.v,4);
    mpz_mul(deltah_tmp,deltah_tmp,e);
    mpz_submul(deltah_tmp,ch.a,ch.a);
    mpz_submul(deltah_tmp,ch.b,ch.b);
    mpz_submul(deltah_tmp,ch.d,ch.d);
    mpz_set(ch.delta,deltah_tmp);
    gmp_printf("Publishing delta-hiding value: %Zd\n\n", ch.delta);

    //mpz_t ah_square; mpz_init(ah_square);
    //mpz_t bh_square; mpz_init(bh_square);
    //mpz_t dh_square; mpz_init(dh_square);

    // free
    mpz_clear(deltah_tmp);



    // verify
    

    // verfy c^e * c = hiding
    mpz_t leftvalue; mpz_init(leftvalue);
    get_commitment(leftvalue,ch);


    mpz_t rightvalue; mpz_init(rightvalue);
    mpz_t rightvalue_tmp; mpz_init(rightvalue_tmp);

    mpz_powm(rightvalue_tmp,c_value,e,n);
    mpz_mul(rightvalue_tmp,rightvalue_tmp,cr_value);
    mpz_powm_ui(rightvalue_tmp,rightvalue_tmp,1,n);
    mpz_set(rightvalue,rightvalue_tmp);

    gmp_printf("Publishing leftvalue: %Zd\n\n",leftvalue);
    gmp_printf("Publishing rightvalue: %Zd\n\n",rightvalue);


    if(mpz_cmp(leftvalue,rightvalue)==0)
    {
      printf("Verification Successful!!!!!!!!!!\n\n");
    }
    else
    {
      printf("Verification Failed!!!\n\n");
    }


 
 
 	//  pbc part
	// commit only one value say v here.
	
	//initialize the pbc here.
	pairing_t pairing;
	
	FILE* fparam = fopen("a.param", "rb");
	char param[1024];
	size_t count = fread(param, 1, 1024, fparam);
	fclose(fparam);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
    int bitlens = pairing_length_in_bytes_Zr(pairing)*8;
    printf("%d bits to represent an element of Zr\n\n",bitlens);
	
	// Setup field.(suported by pbc)
	element_t g_pbc;
	element_t h_pbc;
	
	element_init_G1(g_pbc, pairing);
	element_init_G1(h_pbc, pairing);
	element_random(g_pbc);
	element_random(h_pbc);
    element_printf("After pairing, h_pbc is %B\n\n",h_pbc);
	element_printf("After pairing, g_pbc is %B\n\n",g_pbc);

    // using pbc to generate ox r1 r2 g,h
    element_t x,ox,r1,r2;
    element_init_Zr(x,pairing);
    element_init_Zr(ox,pairing);
    element_init_Zr(r1,pairing);
    element_init_Zr(r2,pairing);
    element_set_mpz(x,c.v);
    element_random(ox);
    element_random(r1);
    element_random(r2);
    element_printf("After pairing and rand, ox is %B\n\n",ox);
    element_printf("After pairing and rand, r1 is %B\n\n",r1);
    element_printf("After pairing and rand, r2 is %B\n\n",r2);


	// commit x
    element_t commit_ecc_v;
    element_init_G1(commit_ecc_v,pairing);
    element_pow2_zn(commit_ecc_v, g_pbc, x, h_pbc , ox);
    element_printf("g^x*h^ox is %B\n\n",commit_ecc_v);
	
	// commit r
    element_t commit_ecc_r;
    element_init_G1(commit_ecc_r,pairing);
    element_pow2_zn(commit_ecc_r, g_pbc, r1, h_pbc , r2);
    element_printf("g^r1*h^r2 is %B\n\n",commit_ecc_r);
	
	
	// here the challenge is the e=hash(CxC'xR1R2)
	element_t hash_value; 
	element_init_Zr(hash_value, pairing);
	element_random(hash_value);
	element_printf("Publishing fake hash value %B\n\n",hash_value);
	// implement this using sha256 later
    
    element_t x_hiding;
	element_t ox_hiding;	
	element_init_Zr(x_hiding,pairing);
	element_init_Zr(ox_hiding,pairing);
	element_mul(x_hiding,hash_value,x);
	element_add(x_hiding,x_hiding,r1);
	element_mul(ox_hiding,hash_value,ox);
	element_add(ox_hiding,ox_hiding,r2);
	
	element_printf("Publishing x hiding value %B\n\n",x_hiding);
	element_printf("Publishing ox hiding value %B\n\n",ox_hiding);
	
	element_t ecc_leftvalue; 
	element_t ecc_rightvalue;
	element_init_G1(ecc_leftvalue,pairing);
    element_init_G1(ecc_rightvalue,pairing);
	element_pow2_zn(ecc_leftvalue,g_pbc,x_hiding,h_pbc,ox_hiding);
	element_t ecc_one; element_init_Zr(ecc_one,pairing);
	element_set1(ecc_one);
	element_pow2_zn(ecc_rightvalue,commit_ecc_v,hash_value,commit_ecc_r,ecc_one);
	
	element_printf("Publishing ecc left value %B\n\n",ecc_leftvalue);
	element_printf("Publishing ecc right value %B\n\n",ecc_rightvalue);
	
	// compare
	if (element_cmp(ecc_leftvalue,ecc_rightvalue)==0)
	{
		printf("ECC commit successful!!\n\n");
	}
	else
	{
		printf("ECC commit failed!!!\n\n");
	}
			
    return 0;

}



void setrndseed()
{
    FILE *rnd;
    mpz_t rndtmp;
    unsigned long int idx;
    time_t t1;
    if (!fastseed) {
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
    else {
        mpz_set_ui(rndseed, (unsigned long int) time(&t1));
    //    mpz_mul_ui(rndseed, rndseed, (unsigned long int) getpid()); 
      //  mpz_mul_ui(rndseed, rndseed, (unsigned long int) getppid());
    }
}

//@TODO create a function
// mpz_t getrnd()



//@TODO add more print for debugging


//@TODO need to make sure those two prime is big enough.
void publish_modulus() {
  mpz_t rand, tmpprime, tmp;
  gmp_randstate_t state;

  mpz_init(rand);
  mpz_init(tmpprime);
  mpz_init(tmp);
  mpz_init(prime1);
  mpz_init(prime2);
  mpz_init(n);

  gmp_randinit_lc_2exp_size(state, 128); 

  /* computes 1st prime */
  setrndseed();

  // 4r+3 except 5
  // 2p+1 p is prime
  gmp_randseed(state, rndseed);
  mpz_rrandomb(rand, state, 1024);
  while (1) {                          /* repeat until prime is of form 4r+3 which is a safe prime*/
    mpz_nextprime(tmpprime, rand);     
    mpz_sub_ui(tmp, tmpprime, 3);
    if (mpz_divisible_ui_p(tmp, 4)) break;
    mpz_set(rand, tmpprime);
  } 
  mpz_set(prime1, tmpprime);

  /* computes 2nd prime */
  setrndseed();
  gmp_randseed(state, rndseed);
  mpz_rrandomb(rand, state, 1024);
  while (1) {                    
    mpz_nextprime(tmpprime, rand);     
    mpz_sub_ui(tmp, tmpprime, 3);
    if (mpz_divisible_ui_p(tmp, 4)) break;
    mpz_set(rand, tmpprime);
  } 
  mpz_set(prime2, tmpprime);

  /* computes modulus */
  mpz_mul(n, prime1, prime2);
  gmp_printf("Publishing modulus: %Zd\n\n", n);
  gmp_printf("Publishing prime1: %Zd\n\n", prime1);
  gmp_printf("Publishing prime2: %Zd\n\n", prime2);
  mpz_clear(rand);
  mpz_clear(tmpprime);
  mpz_clear(tmp);
  gmp_randclear(state);
}


void get_qr_n(mpz_t qr_generator) {


    mpz_t tmp; mpz_init(tmp);
    mpz_t tmp_square; mpz_init(tmp_square);

    while(1) {
      get_element_rand_zn(tmp);

      if ( (mpz_divisible_p(tmp, prime1) == 0) && (mpz_divisible_p(tmp, prime2) == 0) ) break;
    }

    // square and mod n
    mpz_powm_ui (tmp_square, tmp, 2, n);

    mpz_set(qr_generator, tmp_square);
    
    // free
    mpz_clear(tmp_square);
    mpz_clear(tmp);

}

// input must be intialized before pass
void get_element_rand_zn(mpz_t element) {
  //get an element from Zp
  // all element should be initialed.
  gmp_randstate_t state;

  gmp_randinit_lc_2exp_size(state,128);
  setrndseed();

  gmp_randseed(state, rndseed);

  mpz_urandomm(element,state,n);

  gmp_randclear(state);
}

void get_commitment(mpz_t commitment_value,commitment_t cm) {
  
  mpz_t tmp1; mpz_init(tmp1); mpz_powm (tmp1, qr.v,  cm.v,  n);
  mpz_t tmp2; mpz_init(tmp2); mpz_powm (tmp2, qr.a,  cm.a,  n);
  mpz_t tmp3; mpz_init(tmp3); mpz_powm (tmp3,  qr.b,  cm.b,  n);
  mpz_t tmp4; mpz_init(tmp4); mpz_powm (tmp4,  qr.d,  cm.d,  n);
  mpz_t tmp5; mpz_init(tmp5); mpz_powm (tmp5,  qr.delta,  cm.delta,  n);
  //h
  mpz_t tmp6; mpz_init(tmp6); mpz_powm (tmp6,  qr.r,  cm.r,  n);

  mpz_t tmp_mul; mpz_init(tmp_mul);
  mpz_t tmp_result; mpz_init(tmp_result);
  
  //g = g^v * g^a
  mpz_mul(tmp_mul,tmp1,tmp2);
  mpz_powm_ui(tmp_result,tmp_mul,1,n);  //result = mul mod n
  // g = g * g^b
  mpz_mul(tmp_mul,tmp_result,tmp3);
  mpz_powm_ui(tmp_result,tmp_mul,1,n);

  mpz_mul(tmp_mul,tmp_result,tmp4);
  mpz_powm_ui(tmp_result,tmp_mul,1,n);

  mpz_mul(tmp_mul,tmp_result,tmp5);
  mpz_powm_ui(tmp_result,tmp_mul,1,n);

  mpz_mul(tmp_mul,tmp_result,tmp6);
  mpz_powm_ui(tmp_result,tmp_mul,1,n);


  // set the commitment value
  mpz_set(commitment_value,tmp_result);
  //gmp_printf("DEBUG: %Zd\n\n", commitment_value);

  // free
  mpz_clear(tmp1);
  mpz_clear(tmp2);
  mpz_clear(tmp3);
  mpz_clear(tmp4);
  mpz_clear(tmp5);
  mpz_clear(tmp6);
  mpz_clear(tmp_mul);
  mpz_clear(tmp_result);


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

 
void timestamp(FILE *out)
{
  struct tm *tmp;
  time_t t;
 
  t = time(NULL);
  tmp = localtime(&t); /* or gmtime, if you want GMT^H^H^HUTC */
  fprintf(out, "%02d.%02d.%04d %02d:%02d:%02d", 
     tmp->tm_mday, tmp->tm_mon+1, tmp->tm_year+1900,
     tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
}
