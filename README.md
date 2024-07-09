1. mininet:
git clone https://github.com/mininet/mininet
~/mininet/util/install.sh -a
sudo apt update
sudo apt install openvswitch-switch

2. create venv to run ryu-controller:
+ setup python & lib:
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get install virtualenv python3.9 python3.9-distutils
+ create vituralenv:
virtualenv -p`which python3.9` ryu-python3.9-venv
source ryu-python3.9-venv/bin/activate
pip install ryu
pip uninstall eventlet
pip install eventlet==0.30.2
ryu-manager --help
pip install scikit-learn pandas

