./test_speed512 | python3 extract_medians.py > rawbench
./test_speed512_tmp1 | python3 extract_medians.py >> rawbench
./test_speed512_tmp2 | python3 extract_medians.py >> rawbench
./test_speed512_tmp3b | python3 extract_medians.py >> rawbench
python3 table_bench.py < rawbench > table_bench.tex
rm rawbench
./test_speed768 | python3 extract_medians.py > rawbench
./test_speed768_tmp1 | python3 extract_medians.py >> rawbench
./test_speed768_tmp2 | python3 extract_medians.py >> rawbench
./test_speed768_tmp3b | python3 extract_medians.py >> rawbench
python3 table_bench.py < rawbench >> table_bench.tex
rm rawbench
./test_speed1024 | python3 extract_medians.py > rawbench
./test_speed1024_tmp1 | python3 extract_medians.py >> rawbench
./test_speed1024_tmp2 | python3 extract_medians.py >> rawbench
./test_speed1024_tmp3b | python3 extract_medians.py >> rawbench
python3 table_bench.py < rawbench >> table_bench.tex
rm rawbench
