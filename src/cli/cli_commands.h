/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014 Cryptotronix, LLC.
 *
 * This file is part of EClet.
 *
 * EClet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * EClet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with EClet.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef CLI_COMMANDS_H
#define CLI_COMMANDS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libcrypti2c.h>

#define NUM_ARGS 1

#define HASHLET_COMMAND_FAIL EXIT_FAILURE
#define HASHLET_COMMAND_SUCCESS EXIT_SUCCESS

/* Command list */
#define CMD_OFFLINE_VERIFY "offline-verify"
#define CMD_HASH "hash"
#define CMD_OFFLINE_VERIFY_SIGN "offline-verify-sign"

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *args[NUM_ARGS];
  int silent, verbose;
  bool update_seed;
  char *output_file;
  char *input_file;
  unsigned int key_slot;
  bool test;
  uint8_t address;
  const char *challenge;
  const char *challenge_rsp;
  const char *signature;
  const char *pub_key;
  const char *meta;
  const char *write_data;
  const char *bus;
};

struct command
{
  const char *cmd;
  int (*func)(int, struct arguments *);
};

void output_hex (FILE *stream, struct ci2c_octet_buffer buf);

/**
 * Sets reasonable defaults for arguments
 *
 * @param args The argument structure
 */
void set_defaults (struct arguments *args);

/**
 * Dispatch the command for execution.
 *
 * @param command The command to execute
 * @param args The argument structure
 *
 * @return The exit value of the program
 */
int dispatch (const char *command, struct arguments *args);

/**
 * Initialize command line options.  This must be called.
 *
 */
void init_cli (struct arguments * args);

#define NUM_CLI_COMMANDS 15

/**
 * Gets random from the device
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */
int cli_random (int fd, struct arguments *args);

/**
 * Retrieves the device's serial number
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */
int cli_get_serial_num (int fd, struct arguments *args);

/**
 * Retrieves the devices' state
 *
 * @param fd The open File descriptor
 * @param args The argument structure
 *
 * @return The exit code
 */
int cli_get_state (int fd, struct arguments *args);

/**
 * Retrieves the entire config zone from the device
 *
 * @param fd The open file descriptor
 * @param args the argument structure
 *
 * @return the exit code
 */
int cli_get_config_zone (int fd, struct arguments *args);

/**
 * Retrieves the entire OTP Zone
 *
 * @param fd the open file descriptor
 * @param args the argument structure
 *
 * @return the exit code
 */
int cli_get_otp_zone (int fd, struct arguments *args);
/**
 * Performs a straight SHA256 of data, meant for testing purposes
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */
int cli_hash (int fd, struct arguments *args);

/**
 * Perform the device personalization by setting the config zone,
 * writing the OTP zone, and loading keys.  Keys are stored in a file
 * if successful.
 *
 * @param fd The open file descriptor
 * @param args The argument structure
 *
 * @return the exit code
 */
int cli_personalize (int fd, struct arguments *args);

bool is_expected_len (const char* arg, unsigned int len);
bool is_hex_arg (const char* arg, unsigned int len);

/**
 * Reads a data (key) slot.  This command will error if the key slot
 * can't be read.
 *
 * @param fd The open file descriptor
 * @param args The args
 *
 * @return exit code.  If a data slot can't be read, this will return
 * an error.
 */
int cli_read_key_slot (int fd, struct arguments *args);

int cli_gen_key (int fd, struct arguments *args);

/**
 * Perform an ECDSA signature. Data is passed in with the file option
 * or on stdin, which is then hashed with SHA256 prior to signing.
 *
 * @param fd The open file descriptor.
 * @param args The args
 *
 * @return exit code.
 */
int cli_ecc_sign (int fd, struct arguments *args);

/**
 * Verifies an ECC Signature. The signature option is required to
 * provide the signature.
 *
 * @param fd The open file descriptor
 * @param args The arguments
 *
 * @return Success if the signature verified, otherwise error
 */

int
cli_ecc_verify (int fd, struct arguments *args);

/**
 * Retrieve the public key from an ECC private key slot.
 *
 * @param fd The open file descriptor.
 * @param args The arguments, the key slot specifies the key.
 *
 * @return Success or failure code
 */
int
cli_get_pub_key (int fd, struct arguments *args);

/**
 * Performs an ECDSA signature verification without the device.
 *
 * @param fd The open file descriptor
 * @param args The arg
 *
 * @return The status code
 */
int
cli_ecc_offline_verify (int fd, struct arguments *args);

#endif /* CLI_COMMANDS_H */
