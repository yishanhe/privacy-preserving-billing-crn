


%% ECDSA measure
% secp160k1 secp190k1 
% @SEE emails pdf 
ecc190bit = [1.275 1.265 1.269 1.311 1.18 1.345 1.218 1.214 1.265 1.204];
mean_ecc190bit = mean(ecc190bit)
ecc160bit = [1.069 1.041 0.983 0.978 0.998 1.059 1.005 1.097 0.985 1.055];
mean_ecc160bit = mean(ecc160bit)


%% total fee measure
one_mul_time = [0.009 0.009 0.012 0.009 0.009 0.009 0.009 0.009 0.009 0.012];
mean_one_mul_time = mean(one_mul_time)
rest_verify = [0.007 0.007 0.007 0.008 0.007 0.007 0.007 0.008 0.008 0.007];
mean_rest_verify = mean(rest_verify)
 

%% pre-stage publish prime and modulos

%% generate key cl signature
%cl_genkey_time = []
cl_sign_time = [16.0 16.63 15.791 16.19 15.989 15.875 16.459 16.032 16.566 16.117]; 
mean_cl_sign_time = mean(cl_sign_time)
cl_verify_time = [18.38 20.186 18.848 19.047 18.595 18.622 19.669 18.906 19.653 18.986];
mean_cl_verify_time= mean(cl_verify_time)


%% commit pbc
ecc_commit_tuple_time = [13.401 13.194 13.304 12.995 13.782 13.058 13.225 13.121 13.453 13.149];
ecc_commit_total_fee = [4.712 4.187 4.291 4.348 4.604 4.214 4.217 4.141 4.743 4.395];
ecc_verify_commit_tuple_time =[7.418 7.018 7.277 6.951 7.4 7.25 6.914 7.171 7.24 7.059];
ecc_verify_commit_total_fee =[2.492 2.293 2.349 2.313 2.634 2.393 2.394 2.36 2.45 2.357];

mean_ecc_commit_tuple_time=mean(ecc_commit_tuple_time )
mean_ecc_commit_total_fee =mean( ecc_commit_total_fee)
mean_ecc_verify_commit_tuple_time=mean( ecc_verify_commit_tuple_time)
mean_ecc_verify_commit_total_fee =mean( ecc_verify_commit_total_fee)

%% inverval check
prove_interval_time = [31.242 31.66 31.752 32.693 32.223 32.229 31.535 32.443 33.236 32.24];
verify_interval_time = [20.408 21.006 20.897 21.35 21.139 21.252 20.832 21.291 22.043 21.128];

mean_prove_interval_time = mean(prove_interval_time)
mean_verify_interval_time = mean(verify_interval_time)

%% possesion
% @TODO hash
prove_possesion_time = [20.063 20.236 19.953 20.504 20.227 19.924 19.987 20.549 19.634 19.776];
verify_possesion_time = [11.216 11.659 11.186 11.519 11.173 11.184 11.15 11.576 10.977 11.169];
% mean_ = mean()
mean_prove_possesion_time = mean(prove_possesion_time)
mean_verify_possesion_time = mean(verify_possesion_time)

%% product
prove_product_time = [4.986 4.686 4.821 4.781 4.782 4.737 4.651 4.684 4.702 4.841];
verify_product_time = [4.931 4.653 4.806 4.615 4.828 4.706 4.634 4.791 4.765 4.773];
mean_prove_product_time = mean(prove_product_time)
mean_verify_product_time = mean(verify_product_time)

%% total time mean
% total_time_result = [];
% mean_total_time_result = mean(total_time_result)