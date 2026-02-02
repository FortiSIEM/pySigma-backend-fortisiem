./tools/installPkg.sh
python3 backend/app.py &>/dev/null &
echo "Start http server, port: 8888"
python3 -m http.server 8888 &>/dev/null &




