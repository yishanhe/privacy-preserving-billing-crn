close all;
clear;
format long g;
clc;




num_tuple_average=[];
total_time_average=[];
total_time_average_pu=[];
total_time_average_su=[];
save result.mat

for i=1:200
    genTrace
end


%% 
load result.mat

mean_result_tuple_average = mean(num_tuple_average)
mean_result_total_time_average =mean(total_time_average)
mean_result_total_time_average_pu =mean(total_time_average_pu)
mean_result_total_time_average_su =mean(total_time_average_su)
fid = fopen('result.txt','a+');
% fprintf(fid, 'On(mins) Off(mins) Tuples Time(s)  PU   SU\r\n');
 fprintf(fid, ' %2.0f       %2.0f        %4.1f   %4.2f  %4.2f  %4.2f \r\n',...
     mins_on,mins_off,mean_result_tuple_average,mean_result_total_time_average,...
     mean_result_total_time_average_pu,mean_result_total_time_average_su);
fclose(fid);