#include <openssl/bn.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <stdio.h>
//compiled with gcc -g -lssl -UOPENSSL_NO_EC SO2228860.c -lcrypto
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
static int create_signature(unsigned char* hash);

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  main
 *  Description:  test the ecdsad alg
 * =====================================================================================
 */
    int
main ( int argc, char *argv[] )
{
	// generate the random bit for 1024bit 
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	unsigned long int bitlen =1024;
	mpz_t(randnum); mpz_init(randnum);
	mpz_urandomb(randnum,state,bitlen);
	gmp_printf("the rand number is %Zd\n\n",randnum);
	
	char * digest = mpz_get_str(NULL,10,randnum);
	printf("the rand number is %s \n\n",digest);
	
	
	// and change it to char*
	double t0=pbc_get_time();
	int result = create_signature(digest);
	double t1=pbc_get_time();
	printf("To sign a %d bit message using ECDSA cost %lf ms time\n\n",bitlen,(t1-t0)*1000.0);
    return 1;
}				/* ----------  end of function main  ---------- */




static int create_signature(unsigned char* hash)
{
    int function_status = -1;
    EC_KEY *eckey=EC_KEY_new();
    if (NULL == eckey)
    {
        printf("Failed to create new EC Key\n");
        function_status = -1;
    }
    else
    {
        EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp192k1);
        if (NULL == ecgroup)
        {
            printf("Failed to create new EC Group\n");
            function_status = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(eckey,ecgroup);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
                function_status = -1;
            }
            else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(eckey);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                    function_status = -1;
                }
                else
                {
                    ECDSA_SIG *signature = ECDSA_do_sign(hash, strlen(hash), eckey);
                    if (NULL == signature)
                    {
                        printf("Failed to generate EC Signature\n");
                        function_status = -1;
                    }
                    else
                    {
					//	printf("The signature is %s\n\n",signature);
						unsigned char *r_to = malloc(sizeof(char)*BN_num_bytes(signature->r));
						int bool_BN_bn2bin=BN_bn2bin(signature->r, r_to);
						printf("The signature is %s\n\n",r_to);
                        int verify_status = ECDSA_do_verify(hash, strlen(hash), signature, eckey);
                        const int verify_success = 1;
                        if (verify_success != verify_status)
                        {
                            printf("Failed to verify EC Signature\n");
                            function_status = -1;
                        }
                        else
                        {
                            printf("Verifed EC Signature\n");
                            function_status = 1;
                        }
                    }
                }
            }
            EC_GROUP_free(ecgroup);
        }
        EC_KEY_free(eckey);
    }

  return function_status;
}

