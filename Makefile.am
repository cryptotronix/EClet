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

AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = $(DEPS_CFLAGS)
eclet_LDADD = $(DEPS_LIBS)

SUBDIRS = doc .

AM_YFLAGS = -d

bin_PROGRAMS = eclet
eclet_SOURCES = src/driver/command.h src/driver/command.c \
	          src/driver/defs.h \
	          src/cli/main.c \
		  src/driver/personalize.h src/driver/personalize.c \
		  src/cli/cli_commands.h src/cli/cli_commands.c \
		  src/driver/config_zone.h src/driver/config_zone.c

eclet_CFLAGS = -Wall

dist_noinst_SCRIPTS = autogen.sh

TESTS = src/tests/test_cli.sh
EXTRA_DIST = src/tests/test_cli.sh

get-deps:
	git clone https://github.com/cryptotronix/libcrypti2c.git
	cd libcrypti2c && ./autogen.sh && sudo make install && cd ..

.PHONY:	get-deps
