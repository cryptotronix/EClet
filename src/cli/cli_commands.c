/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2013 Cryptotronix, LLC.
 *
 * This file is part of Hashlet.
 *
 * Hashlet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Hashlet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Hashlet.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <assert.h>
#include <string.h>

#include "cli_commands.h"
#include "config.h"
#include "../driver/personalize.h"
// for dev only
#include "../driver/command.h"
#include <libcrypti2c.h>

#if HAVE_GCRYPT_H
#include "hash.h"
#else
#define NO_GCRYPT "Rebuild with libgcrypt to enable this feature"
#endif

static struct command commands[NUM_CLI_COMMANDS];

void
set_defaults (struct arguments *args)
{

  assert (NULL != args);

  args->silent = 0;
  args->verbose = 0;
  args->output_file = "-";
  args->input_file = NULL;
  args->update_seed = false;
  args->key_slot = 0;

  /* Default MAC mode */
  args->mac_mode.use_serial_num = false;
  args->mac_mode.use_otp_0_7 = false;
  args->mac_mode.use_otp_0_10 = false;
  args->mac_mode.temp_key_source_flag = false;
  args->mac_mode.use_first_32_temp_key = false;
  args->mac_mode.use_second_32_temp_key = false;

  args->challenge = NULL;
  args->challenge_rsp = NULL;
  args->meta = NULL;
  args->write_data = NULL;

  args->address = 0x60;
  args->bus = "/dev/i2c-1";


}

void
output_hex (FILE *stream, struct ci2c_octet_buffer buf)
{

  assert (NULL != stream);

  if (NULL == buf.ptr)
    printf ("Command failed\n");
  else
    {
      unsigned int i = 0;

      for (i = 0; i < buf.len; i++)
        {
          fprintf (stream, "%02X", buf.ptr[i]);
        }

      fprintf (stream, "\n");
    }

}

struct command *
find_command (const char* cmd)
{
  int x = 0;

  for (x=0; x < NUM_CLI_COMMANDS; x++)
    {
      const char *cmd_string = commands[x].cmd;
      if (NULL != cmd_string && (0 == strcmp(cmd_string, cmd)))
        return &commands[x];
    }

  return NULL;

}
int
add_command (const struct command cmd, int loc)
{
  assert (loc < NUM_CLI_COMMANDS);

  commands[loc] = cmd;

  return loc+1;
}

void
init_cli (struct arguments *args)
{
  static const struct command random_cmd = {"random", cli_random };
  static const struct command serial_cmd = {"serial-num", cli_get_serial_num };
  static const struct command state_cmd = {"state", cli_get_state };
  static const struct command config_cmd = {"get-config", cli_get_config_zone };
  static const struct command otp_cmd = {"get-otp", cli_get_otp_zone };
  static const struct command personalize_cmd = {"personalize",
                                                 cli_personalize };
  static const struct command nonce_cmd = {"nonce", cli_get_nonce };
  static const struct command dev_cmd = {"dev", cli_dev };
  static const struct command gen_key = {"gen-key", cli_gen_key };
  static const struct command ecc_sign_cmd = {"sign", cli_ecc_sign };
  int x = 0;

  x = add_command (random_cmd, x);
  x = add_command (serial_cmd, x);
  x = add_command (state_cmd, x);
  x = add_command (config_cmd, x);
  x = add_command (otp_cmd, x);
  x = add_command (personalize_cmd, x);
  x = add_command (nonce_cmd, x);
  x = add_command (dev_cmd, x);
  x = add_command (gen_key, x);
  x = add_command (ecc_sign_cmd, x);

  set_defaults (args);

}

bool
cmp_commands (const char *input, const char *cmd)
{
  if (0 == strncmp (cmd, input, strlen (cmd)))
    return true;
  else
    return false;
}

bool
offline_cmd (const char *command)
{
  bool is_offline = false;

  if (NULL == command)
    assert (false);
  else if (cmp_commands (command, CMD_OFFLINE_VERIFY))
    is_offline = true;
  else if (cmp_commands (command, CMD_HASH))
    is_offline = true;

  return is_offline;
}

int
dispatch (const char *command, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  struct command * cmd = NULL;

  const char *bus = args->bus;

  if ((cmd = find_command (command)) == NULL)
    printf ("%s", "Command not found.  Try --help\n");
  else
    {
      assert (NULL != cmd->func);

      int fd = 0;

      if (offline_cmd (command))
        {
          result = (*cmd->func)(fd, args);
        }
      else if ((fd = hashlet_setup (bus, args->address)) < 0)
        perror ("Failed to setup the hashlet");
      else
        {
          result = (*cmd->func)(fd, args);
          hashlet_teardown (fd);
        }


    }

  return result;

}

FILE*
get_input_file (struct arguments *args)
{
  assert (NULL != args);

  FILE* f;

  if (NULL == args->input_file)
    {
      f = stdin;
    }
  else
    {
      f = fopen (args->input_file, "r");
    }

  return f;
}


void
close_input_file (struct arguments *args, FILE *f)
{
  assert (NULL != args);
  assert (NULL != f);

  /* Only close the file if input file was specified */
  if (NULL != args->input_file)
    {
      if (0 != fclose (f))
        perror ("Failed to close input file");
    }
}

bool
is_expected_len (const char* arg, unsigned int len)
{
  assert (NULL != arg);

  bool result = false;
  if (len == strnlen (arg, len+1))
    result = true;

  return result;

}

bool
is_hex_arg (const char* arg, unsigned int len)
{
  if (is_expected_len (arg, len) && ci2c_is_all_hex (arg, len))
    return true;
  else
    return false;
}


int
cli_random (int fd, struct arguments *args)
{

  struct ci2c_octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = get_random (fd, args->update_seed);
  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      ci2c_free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }

  return result;
}

int
cli_get_serial_num (int fd, struct arguments *args)
{
  struct ci2c_octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = get_serial_num (fd);
  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      ci2c_free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }

  return result;

}

int
cli_get_state (int fd, struct arguments *args)
{

  int result = HASHLET_COMMAND_SUCCESS;
  const char *state = "";

  switch (get_device_state (fd))
    {
    case STATE_FACTORY:
      state = "Factory";
      break;
    case STATE_INITIALIZED:
      state = "Initialized";
      break;
    case STATE_PERSONALIZED:
      state = "Personalized";
      break;
    default:
      result = HASHLET_COMMAND_FAIL;
    }

  printf ("%s\n", state);

  return result;


}

int
cli_get_config_zone (int fd, struct arguments *args)
{
  struct ci2c_octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = get_config_zone (fd);
  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      ci2c_free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }

  return result;


}

int cli_get_otp_zone (int fd, struct arguments *args)
{
  struct ci2c_octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  if (STATE_PERSONALIZED != get_device_state (fd))
    {
      fprintf (stderr, "%s\n" ,"Can only read OTP zone when personalized");
      return result;
    }

  response = get_otp_zone (fd);

  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      ci2c_free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }


  return result;


}

int
cli_hash (int fd, struct arguments *args)
{

  struct ci2c_octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

#if HAVE_GCRYPT_H
  FILE *f;
  if ((f = get_input_file (args)) == NULL)
    {
      perror ("Failed to open file");
    }
  else
    {
      response = sha256 (f);
      if (NULL != response.ptr)
        {
          output_hex (stdout, response);
          ci2c_free_octet_buffer (response);
          result = HASHLET_COMMAND_SUCCESS;
        }

      close_input_file (args, f);
    }
#else
  printf ("%s\n", NO_GCRYPT);
#endif

  return result;
}


int
cli_personalize (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  if (STATE_PERSONALIZED != personalize (fd, STATE_PERSONALIZED, NULL))
    printf ("Failure\n");
  else
    result = HASHLET_COMMAND_SUCCESS;

  return result;

}

void
print_mac_result (FILE *fp,
                  struct ci2c_octet_buffer challenge,
                  struct ci2c_octet_buffer mac,
                  struct ci2c_octet_buffer meta)
{
  assert (NULL != fp);
  fprintf (fp, "%s : ", "mac      ");
  output_hex (fp, mac);

  fprintf (fp, "%s : ", "challenge");
  output_hex (fp, challenge);

  fprintf (fp, "%s : ", "meta     ");
  output_hex (fp, meta);

}

int
cli_mac (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

#if HAVE_GCRYPT_H
  struct mac_response rsp;
  struct ci2c_octet_buffer challenge;
  FILE *f;
  if ((f = get_input_file (args)) == NULL)
    {
      perror ("Failed to open file");
    }
  else
    {
      challenge = sha256 (f);
      if (NULL != challenge.ptr)
        {
          rsp = perform_mac (fd, args->mac_mode,
                             args->key_slot, challenge);

          if (rsp.status)
            {
              print_mac_result (stdout, challenge, rsp.mac, rsp.meta);

              ci2c_free_octet_buffer (rsp.mac);
              ci2c_free_octet_buffer (rsp.meta);
              result = HASHLET_COMMAND_SUCCESS;
            }

        ci2c_free_octet_buffer (challenge);
      }

      close_input_file (args, f);
    }
#else
  printf ("%s\n", NO_GCRYPT);
#endif

  return result;
}





int
cli_check_mac (int fd, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  bool mac_cmp = false;
  assert (NULL != args);

  /* TODO: parse encoding from meta data */
  struct check_mac_encoding cm = {0};

  if (NULL == args->challenge)
    fprintf (stderr, "%s\n", "Challenge can't be empty");
  if (NULL == args->challenge_rsp)
    fprintf (stderr, "%s\n", "Challenge Response can't be empty");
  if (NULL == args->meta)
    fprintf (stderr, "%s\n", "Meta data can't be empty");

  if (NULL == args->challenge || NULL == args->challenge_rsp ||
      NULL == args->meta)
    return result;

  struct ci2c_octet_buffer challenge = ci2c_ascii_hex_2_bin (args->challenge, 64);
  struct ci2c_octet_buffer challenge_rsp = ci2c_ascii_hex_2_bin (args->challenge_rsp, 64);
  struct ci2c_octet_buffer meta = ci2c_ascii_hex_2_bin (args->meta, 26);

  mac_cmp = check_mac (fd,  cm, args->key_slot, challenge, challenge_rsp, meta);

  ci2c_free_octet_buffer (challenge);
  ci2c_free_octet_buffer (challenge_rsp);
  ci2c_free_octet_buffer (meta);

  if (mac_cmp)
    result = HASHLET_COMMAND_SUCCESS;
  else
    fprintf (stderr, "%s\n", "Mac miscompare");

  return result;


}

struct encrypted_write
cli_mac_write (int fd, struct ci2c_octet_buffer data,
               unsigned int slot, const char *ascii_key)
{

  struct encrypted_write result;

  struct ci2c_octet_buffer key = {0,0};

  if (NULL != ascii_key)
    {
      key = ci2c_ascii_hex_2_bin (ascii_key, 64);
    }
  else
    {
      CI2C_LOG (DEBUG, "Previous key value not provided");
      return result;
    }


  struct ci2c_octet_buffer otp = get_otp_zone (fd);

  struct ci2c_octet_buffer nonce = get_nonce (fd);

  struct ci2c_octet_buffer nonce_temp_key = gen_temp_key_from_nonce (fd, nonce, otp);

  assert (gen_digest (fd, DATA_ZONE, slot));

  struct ci2c_octet_buffer temp_key = gen_temp_key_from_digest (fd, nonce_temp_key,
                                                           slot, key);

  result.encrypted = ci2c_xor_buffers (temp_key, key);

  const uint8_t opcode = 0x12;
  const uint8_t param1 = 0b10000010;
  uint8_t param2[2] = {0};

  param2[0] = slot_to_addr (DATA_ZONE, slot);
  result.mac = mac_write (temp_key, opcode, param1, param2, data);

  ci2c_print_hex_string ("OTP", otp.ptr, otp.len);

  ci2c_free_octet_buffer (otp);
  ci2c_free_octet_buffer (nonce);
  ci2c_free_octet_buffer (nonce_temp_key);
  ci2c_free_octet_buffer (temp_key);

  return result;

}

int
cli_write_to_key_slot (int fd, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  const unsigned int ASCII_KEY_SIZE = 64;

  struct ci2c_octet_buffer key = {0,0};

  if (NULL == args->write_data)
    fprintf (stderr, "%s\n" ,"Pass the key slot data in the -w option");

  else
    {
      key = ci2c_ascii_hex_2_bin (args->write_data, ASCII_KEY_SIZE);
      if (NULL != key.ptr)
        {
          struct encrypted_write write = cli_mac_write (fd, key, args->key_slot,
                                                        args->challenge);

          if (write.mac.ptr != NULL && write.encrypted.ptr != NULL &&
              write32 (fd, DATA_ZONE,
                       slot_to_addr (DATA_ZONE, args->key_slot),
                       write.encrypted,
                       &write.mac))
            {
              CI2C_LOG (DEBUG, "Write success");
              result = HASHLET_COMMAND_SUCCESS;
            }
          else
            fprintf (stderr, "%s\n" ,"Key slot can not be written.");

          if (NULL != write.mac.ptr)
            ci2c_free_octet_buffer (write.mac);
          if (NULL != write.encrypted.ptr)
            ci2c_free_octet_buffer (write.encrypted);

          ci2c_free_octet_buffer (key);
        }
      else
        {
          fprintf (stderr, "%s\n" ,"Not a valid hex string");
        }
    }

  return result;

}

int
cli_read_key_slot (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct ci2c_octet_buffer buf = {0,0};
  buf = read32 (fd, DATA_ZONE, slot_to_addr (DATA_ZONE, args->key_slot));

  if (NULL != buf.ptr)
    {
      result = HASHLET_COMMAND_SUCCESS;
      output_hex (stdout, buf);
      ci2c_free_octet_buffer (buf);
    }
  else
    fprintf (stderr, "%s%d\n" ,"Data can't be read from key slot: ",
             args->key_slot);

  return result;

}

int
cli_get_nonce (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct ci2c_octet_buffer nonce = get_nonce (fd);

  if (nonce.len == 32 && nonce.ptr != NULL)
    {
      output_hex (stdout, nonce);
      ci2c_free_octet_buffer (nonce);
      result = HASHLET_COMMAND_SUCCESS;
    }
  else
    fprintf (stderr, "%s\n", "Nonce generation failed");


  return result;

}

int
cli_gen_key (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct ci2c_octet_buffer pub_key = gen_ecc_key (fd, args->key_slot, true);

  if (NULL != pub_key.ptr)
    {
      output_hex (stdout, pub_key);
      ci2c_free_octet_buffer (pub_key);
      result = HASHLET_COMMAND_SUCCESS;
    }
  else
    {
      fprintf (stderr, "%s\n", "Gen key commandfailed");
    }

  return result;

}

int
cli_dev (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  bool config_locked = is_config_locked (fd);
  bool data_locked = is_data_locked (fd);

  enum DEVICE_STATE state = get_device_state (fd);

  printf ("%s %d\n", "Config locked", config_locked);
  printf ("%s %d\n", "Data locked", data_locked);

  struct ci2c_octet_buffer pub_key = gen_ecc_key (fd, args->key_slot, true);

  ci2c_print_hex_string ("Pub key", pub_key.ptr, pub_key.len);

  pub_key = gen_ecc_key (fd, args->key_slot, true);
  ci2c_print_hex_string ("Pub key", pub_key.ptr, pub_key.len);

  /* if (set_config_zone (fd)) */
  /*   { */
  /*     printf ("Config zone set\n"); */
  /*     if (lock_config_zone (fd, state)) */
  /*       printf ("Locked"); */
  /*   } */

  /* struct ci2c_octet_buffer otp_zone; */
  /* if (set_otp_zone (fd, &otp_zone)) */
  /*   { */
  /*     if (lock (fd, DATA_ZONE, 0)) */
  /*       { */
  /*         state = STATE_PERSONALIZED; */
  /*         assert (get_device_state (fd) == state); */

  /*         pub_key = gen_ecc_key (fd, args->key_slot, true); */

  /*         ci2c_print_hex_string ("Pub key", pub_key.ptr, pub_key.len); */
  /*       } */

  /*   } */

  return result;




}


int
cli_ecc_sign (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  FILE *f = NULL;

  if ((f = get_input_file (args)) != NULL)
    {
      /* Digest the file then proceed */
      struct ci2c_octet_buffer file_digest = {0,0};
      file_digest = sha256 (f);
      close_input_file (args, f);

      ci2c_print_hex_string ("SHA256 file digest", file_digest.ptr, file_digest.len);

      if (NULL != file_digest.ptr)
        {

          /* struct ci2c_octet_buffer blank_nonce = make_buffer (20); */
          /* struct ci2c_octet_buffer temp_nonce = gen_nonce (fd, */
          /*                                             blank_nonce); */

          struct ci2c_octet_buffer r = get_random (fd, true);
          /* r = get_random (fd, true); */
          /* r = get_random (fd, true); */
          /* r = get_random (fd, false); */

          if (load_nonce (fd, file_digest))
            {

              struct ci2c_octet_buffer rsp = ecc_sign (fd, args->key_slot);

              if (NULL != rsp.ptr)
                {
                  output_hex (stdout, rsp);
                  ci2c_free_octet_buffer (rsp);
                  result = HASHLET_COMMAND_SUCCESS;
                }
              else
                {
                  fprintf (stderr, "%s\n", "Sign Command failed.");
                }

            }

        }
    }
  else
    {
      /* temp_key_loaded already false */
    }


  return result;
}
