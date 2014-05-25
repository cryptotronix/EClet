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

pkg-config --exists crypti2c-0.1
HAVE_CRYPTI2C=$?

if [ $HAVE_CRYPTI2C -eq 0 ]; then
    echo libcrypti2c already installed
else
    git clone https://github.com/cryptotronix/libcrypti2c.git
    cd libcrypti2c
    ./autogen.sh
    echo Enter password to install libcrypti2c library
    sudo make install
    cd ..
    sudo ldconfig
fi

autoreconf --force --install
./configure
make
