
git clone git@github.com:pluginized-protocols/picotcpls.git
cd picotcpls
sudo apt-get update
git submodule update --init
sudo apt-get install  libssl-dev faketime libscope-guard-perl libtest-tcp-perl
cmake .
make
make check
mv *.a ../

