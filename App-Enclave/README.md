README

We have used 2 packages 

1- Libfec (https://github.com/quiet/libfec/blob/master/INSTALL)

2- libjerasure
{
    1-   
    git clone https://github.com/ceph/gf-complete.git

    2-  
    cd gf-complete
    ./autogen.sh
    ./configure
    make
    sudo make install

    3-
    git clone https://github.com/tsuraan/Jerasure.git
    cd Jerasure
    autoreconf --force --install
    ./configure
    make
    sudo make install


}