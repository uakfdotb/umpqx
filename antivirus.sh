echo "Scanning $# files"

for i in "$@"
do
	./umpqx -w map_files/ -now -av listfile_fast.txt "$i"
done
