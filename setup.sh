git clone https://github.com/vm03/payload_dumper
git submodule update --init --recursive
python3 -m pip install -r payload_dumper/requirements.txt
python3 -m pip install -r requirements.txt

# get jadx
mkdir jadx
cd jadx
links=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | grep browser_download_url | cut -d'"' -f4 | grep -E '.zip$' | grep -v 'gui')
wget -q $links -O jadx.zip
unzip jadx.zip 
