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

#include "command.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libcrypti2c.h>
#include "config.h"

struct Command_ATSHA204 make_command ()
{
  struct Command_ATSHA204 c = { .command = 0x03, .count = 0, .opcode = 0,
                                .param1 = 0,
                                .data = NULL, .data_len = 0};

  return c;

}

void set_param1 (struct Command_ATSHA204 *c, uint8_t param1)
{
  assert (NULL != c);

  c->param1 = param1;

}

void set_param2 (struct Command_ATSHA204 *c, uint8_t *param2)
{
  assert (NULL != c);
  assert (NULL != param2);

  c->param2[0] = param2[0];
  c->param2[1] = param2[1];

}

void set_opcode (struct Command_ATSHA204 *c, uint8_t opcode)
{
  assert (NULL != c);

  c->opcode = opcode;

}

void set_data (struct Command_ATSHA204 *c, uint8_t *data, uint8_t len)
{
  assert (NULL != c);

  if (NULL == data || 0 == len)
    {
      c->data = NULL;
      c->data_len = 0;
    }
  else
    {
      c->data = malloc (len);
      assert (NULL != c->data);
      memcpy (c->data, data, len);
      c->data_len = len;
    }


}

void set_execution_time (struct Command_ATSHA204 *c, unsigned int sec,
                        unsigned long nano)
{
  assert (NULL != c);
  c->exec_time.tv_sec = sec;
  c->exec_time.tv_nsec = nano;

}

void print_command (struct Command_ATSHA204 *c)
{
  assert (NULL != c);

  const char* opcode = NULL;

  CI2C_LOG (DEBUG, "*** Printing Command ***");
  CI2C_LOG (DEBUG, "Command: 0x%02X", c->command);
  CI2C_LOG (DEBUG, "Count: 0x%02X", c->count);
  CI2C_LOG (DEBUG, "OpCode: 0x%02X", c->opcode);

  switch (c->opcode)
    {
    case COMMAND_DERIVE_KEY:
      opcode = "Command Derive Key";
      break;
    case COMMAND_DEV_REV:
      opcode = "Command Dev Rev";
      break;
    case COMMAND_GEN_DIG:
      opcode = "Command Generate Digest";
      break;
    case COMMAND_HMAC:
      opcode = "Command HMAC";
      break;
    case COMMAND_CHECK_MAC:
      opcode = "Command Check MAC";
      break;
    case COMMAND_LOCK:
      opcode = "Command Lock";
      break;
    case COMMAND_MAC:
      opcode = "Command MAC";
      break;
    case COMMAND_NONCE:
      opcode = "Command NONCE";
      break;
    case COMMAND_PAUSE:
      opcode = "Command Pause";
      break;
    case COMMAND_RANDOM:
      opcode = "Command Random";
      break;
    case COMMAND_READ:
      opcode = "Command Read";
      break;
    case COMMAND_UPDATE_EXTRA:
      opcode = "Command Update Extra";
      break;
    case COMMAND_WRITE:
      opcode = "Command Write";
      break;
    case COMMAND_GEN_KEY:
      opcode = "Command Gen ECC Key";
      break;
    case COMMAND_ECC_SIGN:
      opcode = "Command ECC Sign Key";
      break;
    case COMMAND_ECC_VERIFY:
      opcode = "Command ECC Verify";
      break;
    default:
      assert (false);
    }
  CI2C_LOG (DEBUG,"%s", opcode);
  CI2C_LOG (DEBUG,"param1: 0x%02X", c->param1);
  CI2C_LOG (DEBUG,"param2: 0x%02X 0x%02X", c->param2[0], c->param2[1]);
  if (c->data_len > 0)
    ci2c_print_hex_string ("Data", c->data, c->data_len);
  CI2C_LOG (DEBUG,"CRC: 0x%02X 0x%02X", c->checksum[0], c->checksum[1]);
  CI2C_LOG (DEBUG,"Wait time: %ld seconds %lu nanoseconds",
          c->exec_time.tv_sec, c->exec_time.tv_nsec);



}

enum CI2C_STATUS_RESPONSE
get_status_response(const uint8_t *rsp)
{
  const unsigned int OFFSET_TO_CRC = 2;
  const unsigned int OFFSET_TO_RSP = 1;
  const unsigned int STATUS_LENGTH = 4;

  if (!ci2c_is_crc_16_valid (rsp, STATUS_LENGTH - CI2C_CRC_16_LEN,
                             rsp + OFFSET_TO_CRC))
    {
      CI2C_LOG (DEBUG, "CRC Fail in status response");
      return RSP_COMM_ERROR;
    }

  return *(rsp + OFFSET_TO_RSP);

}


struct ci2c_octet_buffer
get_random (int fd, bool update_seed)
{
  uint8_t *random = NULL;
  uint8_t param2[2] = {0};
  uint8_t param1 = update_seed ? 0 : 1;
  struct ci2c_octet_buffer buf = {};

  random = ci2c_malloc_wipe (RANDOM_RSP_LENGTH);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_RANDOM);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, RANDOM_AVG_EXEC);

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, random, RANDOM_RSP_LENGTH))
    {
      buf.ptr = random;
      buf.len = RANDOM_RSP_LENGTH;
    }
  else
    CI2C_LOG (DEBUG, "Random command failed");

  return buf;



}

uint8_t set_zone_bits (enum DATA_ZONE zone)
{
  uint8_t z;

  switch (zone)
    {
    case CONFIG_ZONE:
      z = 0b00000000;
      break;
    case OTP_ZONE:
      z = 0b00000001;
      break;
    case DATA_ZONE:
      z = 0b00000010;
      break;
    default:
      assert (false);

    }

  return z;

}

bool read4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t *buf)
{

  bool result = false;
  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  assert (NULL != buf);

  param2[0] = addr;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_READ);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, 1000000);


  if (RSP_SUCCESS == ci2c_process_command (fd, &c, (uint8_t *)buf, sizeof (uint32_t)))
    {
      result = true;
    }

  return result;
}

struct ci2c_octet_buffer read32 (int fd, enum DATA_ZONE zone, uint8_t addr)
{


  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  uint8_t READ_32_MASK = 0b10000000;

  param1 |= READ_32_MASK;

  param2[0] = addr;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_READ);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, READ_AVG_EXEC);

  const unsigned int LENGTH_OF_RESPONSE = 32;
  struct ci2c_octet_buffer buf = ci2c_make_buffer (LENGTH_OF_RESPONSE);

  if (RSP_SUCCESS != ci2c_process_command (fd, &c, buf.ptr, LENGTH_OF_RESPONSE))
    {
      ci2c_free_wipe (buf.ptr, LENGTH_OF_RESPONSE);
      buf.ptr = NULL;
      buf.len = 0;
    }

  return buf;
}



bool write4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t buf)
{

  bool status = false;
  uint8_t recv = 0;
  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  param2[0] = addr;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_WRITE);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, (uint8_t *)&buf, sizeof (buf));
  set_execution_time (&c, 0, 4000000);

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, &recv, sizeof (recv)))
  {
    if (0 == (int) recv)
      status = true;
  }

  return status;



}

bool write32 (int fd, enum DATA_ZONE zone, uint8_t addr,
              struct ci2c_octet_buffer buf, struct ci2c_octet_buffer *mac)
{

  assert (NULL != buf.ptr);
  assert (32 == buf.len);
  if (NULL != mac)
    assert (NULL != mac->ptr);

  bool status = false;
  uint8_t recv = 0;
  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  struct ci2c_octet_buffer data = {0,0};

  if (NULL != mac)
    data = ci2c_make_buffer (buf.len + mac->len);
  else
    data = ci2c_make_buffer (buf.len);

  memcpy (data.ptr, buf.ptr, buf.len);
  if (NULL != mac && mac->len > 0)
    memcpy (data.ptr + buf.len, mac->ptr, mac->len);

  /* If writing 32 bytes, this bit must be set in param1 */
  uint8_t WRITE_32_MASK = 0b10000000;

  param1 |= WRITE_32_MASK;

  param2[0] = addr;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_WRITE);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, data.ptr, data.len);

  set_execution_time (&c, 0, WRITE_AVG_EXEC);

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, &recv, sizeof (recv)))
  {
    CI2C_LOG (DEBUG, "Write 32 successful.");
    if (0 == (int) recv)
      status = true;
  }

  ci2c_free_octet_buffer (data);

  return status;



}



bool is_locked (int fd, enum DATA_ZONE zone)
{
  const uint8_t config_addr = 0x10;
  const uint8_t UNLOCKED = 0x55;
  bool result = true;
  const unsigned int CONFIG_ZONE_OFFSET = 23;
  const unsigned int DATA_ZONE_OFFSET = 22;
  unsigned int offset = 0;
  uint8_t * ptr = NULL;

  switch (zone)
    {
    case CONFIG_ZONE:
      offset = CONFIG_ZONE_OFFSET;
      break;
    case DATA_ZONE:
    case OTP_ZONE:
      offset = DATA_ZONE_OFFSET;
      break;
    default:
      assert (false);

    }

  struct ci2c_octet_buffer config_data = read32 (fd, CONFIG_ZONE, config_addr);

  if (config_data.ptr != NULL)
    {
      ptr = config_data.ptr + offset;
      if (UNLOCKED == *ptr)
        result = false;
      else
        result = true;

      ci2c_free_octet_buffer (config_data);
    }

  return result;
}

bool is_config_locked (int fd)
{
  return is_locked (fd, CONFIG_ZONE);
}

bool is_data_locked (int fd)
{
  return is_locked (fd, DATA_ZONE);
}


struct ci2c_octet_buffer get_config_zone (fd)
{
  const unsigned int SIZE_OF_CONFIG_ZONE = 128;
  const unsigned int NUM_OF_WORDS = SIZE_OF_CONFIG_ZONE / 4;

  struct ci2c_octet_buffer buf = ci2c_make_buffer (SIZE_OF_CONFIG_ZONE);
  uint8_t *write_loc = buf.ptr;

  unsigned int addr = 0;
  unsigned int word = 0;

  while (word < NUM_OF_WORDS)
    {
      addr = word * 4;
      read4 (fd, CONFIG_ZONE, word, (uint32_t*)(write_loc+addr));
      word++;
    }

  return buf;
}

struct ci2c_octet_buffer get_otp_zone (fd)
{
    const unsigned int SIZE_OF_OTP_ZONE = 64;
    const unsigned int SIZE_OF_READ = 32;
    const unsigned int SIZE_OF_WORD = 4;
    const unsigned int SECOND_WORD = (SIZE_OF_READ / SIZE_OF_WORD);

    struct ci2c_octet_buffer buf = ci2c_make_buffer (SIZE_OF_OTP_ZONE);
    struct ci2c_octet_buffer half;

    int x = 0;

    for (x=0; x < 2; x++ )
      {
        int addr = x * SECOND_WORD;
        int offset = x * SIZE_OF_READ;

        half = read32 (fd, OTP_ZONE, addr);
        if (NULL != half.ptr)
          {
            memcpy (buf.ptr + offset, half.ptr, SIZE_OF_READ);
            ci2c_free_octet_buffer (half);
          }
        else
          {
            ci2c_free_octet_buffer (buf);
            buf.ptr = NULL;
            return buf;
          }

      }

    return buf;
}

bool lock (int fd, enum DATA_ZONE zone, uint16_t crc)
{

  uint8_t param1 = 0;
  uint8_t param2[2];
  uint8_t response;
  bool result = false;

  if (is_locked (fd, zone))
    return true;

  memcpy (param2, &crc, sizeof (param2));

  const uint8_t CONFIG_MASK = 0;
  const uint8_t DATA_MASK = 1;

  switch (zone)
    {
    case CONFIG_ZONE:
      param1 |= CONFIG_MASK;
      break;
    case DATA_ZONE:
    case OTP_ZONE:
      param1 |= DATA_MASK;
      break;
    default:
      assert (false);
    }

  /* ignore the crc */
  param1 |= 0x80;
  crc = 0;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_LOCK);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, LOCK_AVG_EXEC);

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, &response, sizeof (response)))
    {
      if (0 == response)
        {
          result = true;
          CI2C_LOG (DEBUG, "Lock Successful");
        }
      else
        {
          CI2C_LOG (DEBUG, "Lock Failed");
        }
    }


  return result;

}

bool is_otp_read_only_mode (int fd)
{
  const uint8_t ADDR = 0x04;
  uint32_t word = 0;
  assert (read4 (fd, CONFIG_ZONE, ADDR, &word));

  uint8_t * byte = (uint8_t *)&word;

  const unsigned int OFFSET_TO_OTP_MODE = 2;
  const unsigned int OTP_READ_ONLY_MODE = 0xAA;

  return OTP_READ_ONLY_MODE == byte[OFFSET_TO_OTP_MODE] ? true : false;


}


bool set_otp_zone (int fd, struct ci2c_octet_buffer *otp_zone)
{

  assert (NULL != otp_zone);

  const unsigned int SIZE_OF_WRITE = 32;
  /* The device must be using an OTP read only mode */

  if (!is_otp_read_only_mode (fd))
    assert (false);

  /* The writes must be done in 32 bytes blocks */

  uint8_t nulls[SIZE_OF_WRITE];
  uint8_t part1[SIZE_OF_WRITE];
  uint8_t part2[SIZE_OF_WRITE];
  struct ci2c_octet_buffer buf ={};
  ci2c_wipe (nulls, SIZE_OF_WRITE);
  ci2c_wipe (part1, SIZE_OF_WRITE);
  ci2c_wipe (part2, SIZE_OF_WRITE);

  /* Simple check to make sure PACKAGE_VERSION isn't too long */
  assert (strlen (PACKAGE_VERSION) < 10);

  /* Setup the fixed OTP data zone */
  sprintf ((char *)part1, "CRYPTOTRONIX ECLET REV: A");
  sprintf ((char *)part2, "SOFTWARE VERSION: %s", PACKAGE_VERSION);

  bool success = true;

  buf.ptr = nulls;
  buf.len = sizeof (nulls);

  /* Fill the OTP zone with blanks from their default FFFF */
  success = write32 (fd, OTP_ZONE, 0, buf, NULL);

  if (success)
    success = write32 (fd, OTP_ZONE, SIZE_OF_WRITE / sizeof (uint32_t),
                       buf, NULL);

  /* Fill in the data */
  buf.ptr = part1;
  CI2C_LOG (DEBUG, "Writing: %s", buf.ptr);
  if (success)
    success = write32 (fd, OTP_ZONE, 0, buf, NULL);
  buf.ptr = part2;
  CI2C_LOG (DEBUG, "Writing: %s", buf.ptr);
  if (success)
    success = write32 (fd, OTP_ZONE, SIZE_OF_WRITE / sizeof (uint32_t),
                       buf, NULL);

  /* Lastly, copy the OTP zone into one contiguous buffer.
     Ironically, the OTP can't be read while unlocked. */
  if (success)
    {
      otp_zone->len = SIZE_OF_WRITE * 2;
      otp_zone->ptr = ci2c_malloc_wipe (otp_zone->len);
      memcpy (otp_zone->ptr, part1, SIZE_OF_WRITE);
      memcpy (otp_zone->ptr + SIZE_OF_WRITE, part2, SIZE_OF_WRITE);
    }
  return success;
}


struct ci2c_octet_buffer get_serial_num (int fd)
{
  struct ci2c_octet_buffer serial;
  const unsigned int len = sizeof (uint32_t) * 2 + 1;
  serial.ptr = ci2c_malloc_wipe (len);
  serial.len = len;

  uint32_t word = 0;

  const uint8_t SERIAL_PART1_ADDR = 0x00;
  const uint8_t SERIAL_PART2_ADDR = 0x02;
  const uint8_t SERIAL_PART3_ADDR = 0x03;

  read4 (fd, CONFIG_ZONE, SERIAL_PART1_ADDR, &word);
  memcpy (serial.ptr, &word, sizeof (word));

  read4 (fd, CONFIG_ZONE, SERIAL_PART2_ADDR, &word);
  memcpy (serial.ptr + sizeof (word), &word, sizeof (word));

  read4 (fd, CONFIG_ZONE, SERIAL_PART3_ADDR, &word);

  uint8_t * ptr = (uint8_t *)&word;

  memcpy (serial.ptr + len - 1, ptr, 1);

  return serial;

}


enum DEVICE_STATE get_device_state (int fd)
{
  bool config_locked;
  bool data_locked;
  enum DEVICE_STATE state = STATE_FACTORY;

  config_locked = is_config_locked (fd);
  data_locked = is_data_locked (fd);

  if (!config_locked && !data_locked)
    state = STATE_FACTORY;
  else if (config_locked && !data_locked)
    state = STATE_INITIALIZED;
  else if (config_locked && data_locked)
    state = STATE_PERSONALIZED;
  else
    assert (false);

  return state;

}

uint8_t slot_to_addr (enum DATA_ZONE zone, uint8_t slot)
{
    switch (zone)
      {
      case DATA_ZONE:
        assert (0 <= slot && slot <= 15);
        break;

      case OTP_ZONE:
        assert (0 == slot || 1 == slot);
        break;

      case CONFIG_ZONE:
        assert (0 <= slot && slot <= 2);
        break;

      default:
        assert (false);
      }

    slot <<= 3;

    return slot;

}

struct ci2c_octet_buffer gen_nonce (int fd, struct ci2c_octet_buffer data)
{
  const unsigned int EXTERNAL_INPUT_LEN = 32;
  const unsigned int NEW_NONCE_LEN = 20;

  assert (NULL != data.ptr && (EXTERNAL_INPUT_LEN == data.len ||
                               NEW_NONCE_LEN == data.len));

  uint8_t param2[2] = {0};
  uint8_t param1 = 0;

  unsigned int rsp_len = 0;

  if (EXTERNAL_INPUT_LEN == data.len)
    {
      const unsigned int PASS_THROUGH_MODE = 3;
      const unsigned int RSP_LENGTH = 1;
      param1 = PASS_THROUGH_MODE;
      rsp_len = RSP_LENGTH;
    }
  else
    {
      const unsigned int COMBINE_AND_UPDATE_SEED = 0;
      const unsigned int RSP_LENGTH = 32;
      param1 = COMBINE_AND_UPDATE_SEED;
      rsp_len = RSP_LENGTH;
    }

  struct ci2c_octet_buffer buf = ci2c_make_buffer (rsp_len);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_NONCE);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, data.ptr, data.len);
  set_execution_time (&c, 0, NONCE_AVG_EXEC);

  if (RSP_SUCCESS != ci2c_process_command (fd, &c, buf.ptr, buf.len))
    {
      CI2C_LOG (DEBUG, "Nonce command failed");
      ci2c_free_octet_buffer (buf);
      buf.ptr = NULL;
    }

  return buf;



}

struct ci2c_octet_buffer get_nonce (int fd)
{
  struct ci2c_octet_buffer otp;
  struct ci2c_octet_buffer nonce = {0, 0};
  const unsigned int MIX_DATA_LEN = 20;

  otp = get_otp_zone (fd);
  unsigned int otp_len = otp.len;

  if (otp.len > MIX_DATA_LEN && otp.ptr != NULL)
    {
      otp.len = MIX_DATA_LEN;
      nonce = gen_nonce (fd, otp);
      otp.len = otp_len;

    }

  ci2c_free_octet_buffer (otp);

  return nonce;
}


bool load_nonce (int fd, struct ci2c_octet_buffer data)
{
  assert (data.ptr != NULL && data.len == 32);

  struct ci2c_octet_buffer rsp = gen_nonce (fd, data);

  if (NULL == rsp.ptr || *rsp.ptr != 0)
    return false;
  else
    return true;

}


struct ci2c_octet_buffer gen_ecc_key (int fd, uint8_t key_id, bool private)
{

  assert (key_id <= 15);

  uint8_t param2[2] = {0};
  uint8_t param1 = 0;

  param2[0] = key_id;

  if (private)
    {
      param1 = 0x04; /* Private key */
    }
  else
    {
      param1 = 0x00; /* Gen public key from private key in the slot */
    }

  struct ci2c_octet_buffer pub_key = ci2c_make_buffer (64);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_GEN_KEY);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, GEN_KEY_AVG_EXEC);

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, pub_key.ptr, pub_key.len))
    {
      CI2C_LOG (DEBUG, "Gen key success");
    }
  else
    {
      CI2C_LOG (DEBUG, "Gen key failure");
      ci2c_free_octet_buffer (pub_key);
      pub_key.ptr = NULL;
    }

  return pub_key;

}


struct ci2c_octet_buffer ecc_sign (int fd, uint8_t key_id)
{

  assert (key_id <= 15);

  uint8_t param2[2] = {0};
  uint8_t param1 = 0x80; /* external signatures only */

  param2[0] = key_id;

  struct ci2c_octet_buffer signature = ci2c_make_buffer (64);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_ECC_SIGN);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, ECC_SIGN_MAX_EXEC);

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, signature.ptr, signature.len))
    {
      CI2C_LOG (DEBUG, "Sign success");
    }
  else
    {
      CI2C_LOG (DEBUG, "Sign failure");
      ci2c_free_octet_buffer (signature);
      signature.ptr = NULL;
    }

  return signature;


}


bool
ecc_verify (int fd,
            struct ci2c_octet_buffer pub_key,
            struct ci2c_octet_buffer signature)
{

  assert (NULL != signature.ptr);
  assert (64 == signature.len); /* P256 signatures are 64 bytes */

  assert (NULL != pub_key.ptr);
  assert (64 == pub_key.len); /* P256 Public Keys are 64 bytes */

  uint8_t param2[2] = {0};
  uint8_t param1 = 0x02; /* Currently only support external keys */

  param2[0] = 0x04; /* Currently only support P256 Keys */

  struct ci2c_octet_buffer payload =
    ci2c_make_buffer (signature.len + pub_key.len);

  memcpy (payload.ptr, signature.ptr, signature.len);
  memcpy (payload.ptr + signature.len, pub_key.ptr, pub_key.len);

  uint8_t result = 0xFF;
  bool verified = false;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_ECC_VERIFY);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, payload.ptr, payload.len);
  set_execution_time (&c, 0, ECC_VERIFY_MAX_EXEC);

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, &result, sizeof(result)))
    {
      CI2C_LOG (DEBUG, "Verify success");
      verified = true;
    }
  else
    {
      CI2C_LOG (DEBUG, "Verify failure");
    }

  ci2c_free_octet_buffer (payload);

  return verified;


}
