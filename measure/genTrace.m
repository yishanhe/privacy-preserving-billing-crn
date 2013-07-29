close all;
clear;
format long g;
clc;

% load our meansurement
result_record

mins_on = 40;
mins_off = 60;
% assume that the time unit is second
% 24 hours = 24*60 mins = 24*60*60 s
mean_on = mins_on*60; 
mean_off = mins_off*60;
 prob_busy = mean_on/(mean_on+mean_off);
current_time = 0;
tuple  = [];




% starts from off;
i=1;
while current_time <= 24*60*60
    tuple(i,1)=i; %index
    tuple(i,2)=0; %off
    tuple(i,3)=current_time;
    current_time=current_time+exprnd(mean_off);
    tuple(i,4)=current_time;
    tuple(i,5)=tuple(i,4)-tuple(i,3); % duration
    i=i+1;
    tuple(i,1)=i; %index
    tuple(i,2)=1; %on
    tuple(i,3)=current_time;
    current_time=current_time+exprnd(mean_on);
    tuple(i,4)=current_time;
     tuple(i,5)=tuple(i,4)-tuple(i,3); % duration
    i=i+1;
end

% usage
usage = tuple(tuple(:,2)==1,[3,4,5]) ; % start time - end time duration
num_tuple = length(usage);


%% policy sign and verify
% 1 
% send three policy
% verify three policy

% add policy and price
policy1=[0,8*60*60];
price1=0.5;
policy2=[8*60*60,18*60*60];
price2=1;
policy3=[18*60*60,24*60*60];
price3=2;

num_policy = 3;
cl_time_vector = [mean_cl_sign_time mean_cl_verify_time];
%%%%%%%%%%
policy_sign_verify_time = sum(cl_time_vector)*num_policy;
%%%%%%%%%%%

%% commitment and verify 
% @TODO plus one time ecdsa time
% mean_ecc_commit_tuple_time=mean(ecc_commit_tuple_time )
% mean_ecc_commit_total_fee =mean( ecc_commit_total_fee)
% mean_ecc_verify_commit_tuple_time=mean( ecc_verify_commit_tuple_time)
% mean_ecc_verify_commit_total_fee =mean( ecc_verify_commit_total_fee)

%%%%%%%%%%%%%%
ecc_commit_verify_time = num_tuple*(mean_ecc_commit_tuple_time+mean_ecc_verify_commit_tuple_time)+mean_ecc_commit_total_fee+mean_ecc_verify_commit_total_fee;
pu1= num_tuple*(mean_ecc_verify_commit_tuple_time)+mean_ecc_verify_commit_total_fee;
su1= num_tuple*(mean_ecc_commit_tuple_time)+mean_ecc_commit_total_fee;
%%%%%%%%%%%%%%%%

%% prove inteval 
% each tuple 2 interval
% mean_prove_interval_time
% mean_verify_interval_time

%%%%%%%%%%%%%%%%%%
interval_prove_verify_time = 2*num_tuple*(mean_prove_interval_time+mean_verify_interval_time);
pu2=2*num_tuple*(mean_verify_interval_time);
su2=2*num_tuple*(mean_prove_interval_time);
%%%%%%%%%%%%%%%%%%%

%% prove possesion of the signature
%%%%%%%%%%%%%%%%%%%
possesion_prove_verify_time = num_tuple*(mean_prove_possesion_time+mean_verify_possesion_time);
pu3=num_tuple*(mean_verify_possesion_time);
su3=num_tuple*(mean_prove_possesion_time);
%%%%%%%%%%%%%%%%%%%%%%

%% prove product
%%%%%%%%%%%%%%%
product_prove_verify_time = num_tuple*(mean_prove_product_time+mean_verify_product_time);
pu4= num_tuple*(mean_verify_product_time);
su4= num_tuple*(mean_prove_product_time);
%%%%%%%%%%%%%%

%% verify total fee
total_fee_verify_time_vector=[mean_one_mul_time,mean_rest_verify];
%%%%%%%%%
total_fee_verify_time = total_fee_verify_time_vector(1)*num_tuple + total_fee_verify_time_vector(2)
%%%%%%%%%%%





% assume that
% 24 hours
% 0-8 0.5
% 8-18 1
% 18-24 2
display('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$');
% the time unit is 3
mean_on 
mean_off
num_tuple 
prob_busy
total_time_with_policy = (total_fee_verify_time+product_prove_verify_time+possesion_prove_verify_time+interval_prove_verify_time+ecc_commit_verify_time+policy_sign_verify_time)/1000
total_time_without_policy = (total_fee_verify_time+product_prove_verify_time+possesion_prove_verify_time+interval_prove_verify_time+ecc_commit_verify_time)/1000
total_pu = (total_fee_verify_time+pu1 +pu2+pu3+pu4)/1000;
total_su = (su1+su2+su3+su4)/1000;
display('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$');

% num_tuple_average=[]
% total_time_average=[]
% save result.mat

load result.mat 
num_tuple_average=[num_tuple_average num_tuple];
total_time_average=[total_time_average total_time_without_policy];
total_time_average_pu=[total_time_average_pu total_pu];
total_time_average_su=[total_time_average_su total_su];
save result.mat num_tuple_average total_time_average total_time_average_pu total_time_average_su