# Copyright (C) 2014 Cryptotronix, LLC.

# This file is part of EClet.

# EClet is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# EClet is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with EClet.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT([eclet], [0.1.1], [bugs@cryptotronix.com], [eclet], [http://www.github.com/cryptotronix/EClet/])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Wall no-define])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADERS([linux/i2c-dev.h sys/ioctl.h fcntl.h])
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_FILES([Makefile doc/Makefile])
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([DEPS], [cryptoauth-0.2])
AC_PROG_LIBTOOL


AC_OUTPUT
