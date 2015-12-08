#!/bin/bash
# Copyright (C) 2013 Cryptotronix, LLC.

# This file is part of Hashlet.

# Hashlet is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# Hashlet is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Hashlet.  If not, see <http://www.gnu.org/licenses/>.

if [ ! -d "m4" ]; then
    mkdir m4
fi

pkg-config --exists cryptoauth-0.2
HAVE_CRYPTI2C=$?

if [ $HAVE_CRYPTI2C -eq 0 ]; then
    echo libcryptoauth already installed
else
    rm -rf libcryptoauth-0.2
    wget -c https://github.com/cryptotronix/libcrypti2c/releases/download/v0.2/libcryptoauth-0.2.tar.gz
    tar xf libcryptoauth-0.2.tar.gz
    cd libcryptoauth-0.2
    ./configure
    make
    echo Enter password to install libcrypti2c library
    sudo make install
    cd ..
    sudo ldconfig
fi

echo Generating README prerequisite...
egrep -v "\[Build Status\]|Coverity Scan Build Status|scan\.coverity\.com" README.md \
  | markdown \
  | html2text -style pretty -nobs \
  > README

echo Running autoreconf...
autoreconf --force --install

echo Configuring...
./configure

echo Making...
make

