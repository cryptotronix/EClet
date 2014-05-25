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
#include <sys/types.h>
#include <fcntl.h>
#include "config.h"
#include "personalize.h"
#include <libcrypti2c.h>
#include "config_zone.h"

unsigned int
get_max_keys ()
{
  return MAX_NUM_DATA_SLOTS;
}


struct key_container*
make_key_container (void)
{
  return (struct key_container *)ci2c_malloc_wipe ( sizeof (struct key_container));
}


void free_key_container (struct key_container *keys)
{
  assert (NULL != keys);

  unsigned int x = 0;

  for (x=0; x < get_max_keys (); x++)
    {
      if (NULL != keys->keys[x].ptr)
        ci2c_free_octet_buffer (keys->keys[x]);
    }

  free (keys);

}


uint16_t
crc_data_otp_zone (struct ci2c_octet_buffer data, struct ci2c_octet_buffer otp)
{
  const unsigned int len = otp.len + data.len;
  uint8_t *buf = ci2c_malloc_wipe (len);

  memcpy (buf, data.ptr, data.len);
  memcpy (buf + data.len, otp.ptr, otp.len);

  uint16_t crc = ci2c_calculate_crc16 (buf, len);

  ci2c_free_wipe (buf, len);

  return crc;

}

bool lock_config_zone (int fd, enum DEVICE_STATE state)
{

  if (STATE_FACTORY != state)
    return true;

  struct ci2c_octet_buffer config = get_config_zone (fd);

  uint16_t crc = ci2c_calculate_crc16 (config.ptr, config.len);

  return lock (fd, CONFIG_ZONE, crc);

}


enum DEVICE_STATE personalize (int fd, enum DEVICE_STATE goal,
                               struct key_container *keys)
{

  enum DEVICE_STATE state = get_device_state (fd);

  if (state >= goal)
    return state;

  if (set_config_zone (fd) && lock_config_zone (fd, state))
    {
      state = STATE_INITIALIZED;
      assert (get_device_state (fd) == state);

      struct ci2c_octet_buffer otp_zone;
      if (set_otp_zone (fd, &otp_zone))
        #warning Need to CRC zone prior to locking!
        {
          /* struct ci2c_octet_buffer data_zone; */
          /* if (write_keys (fd, keys, &data_zone)) */
          /*   { */
          /*     uint16_t crc = crc_data_otp_zone (data_zone, otp_zone); */

          /*     if (lock (fd, DATA_ZONE, crc)) */
          /*       { */
          /*         state = STATE_PERSONALIZED; */
          /*         assert (get_device_state (fd) == state); */
          /*       } */

          /*     ci2c_free_octet_buffer (data_zone); */
          /*   } */

              if (lock (fd, DATA_ZONE, 0))
                {
                  state = STATE_PERSONALIZED;
                  assert (get_device_state (fd) == state);
                }

          ci2c_free_octet_buffer (otp_zone);
        }
    }

  return state;

}
