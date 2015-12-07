EClet
=====

[![Build Status](https://travis-ci.org/cryptotronix/EClet.png)](https://travis-ci.org/cryptotronix/EClet)
<a href="https://scan.coverity.com/projects/4781">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/4781/badge.svg"/>
</a>

Driver for the Cryptotronix EClet containing an Atmel ATECC108

Status
---

This software is in ***BETA***. I have tested the below commands, but some there are some features and documentation that I would like to finish. If you use this software, it will configure your ECC108 in a non-reversible way. It will allow you to sign and verify with P256 keys but future features may be incompatible.

Releases
-----

You can download the latest release [here](https://github.com/cryptotronix/EClet/releases/download/0.1.1/eclet-0.1.1.tar.gz). You will also need [this](https://github.com/cryptotronix/libcrypti2c/releases/download/v0.2/libcryptoauth-0.2.tar.gz) release of libcryptoauth.

Building
----

This project uses Autotools.

It requires [libcryptoauth-0.2](https://github.com/cryptotronix/libcrypti2c), also in ***BETA***. If you use the [autogen](https://github.com/cryptotronix/EClet/blob/master/autogen.sh) script, it will automatically build and install the library.

Also ensure that gcc, automake, autoconf, libxml2-dev, check and libgcrypt (libgcrypt11-dev on Debian variants) are installed

Then run ./autogen.sh

Hardware
---

The Hardware folder has an example board layout. This software will also work on the [CryptoCape](https://www.sparkfun.com/products/12773).

Running
---

see `./eclet --help` for full details.  The default I2C bus is
`/dev/i2c-1` and this can be changed with the `-b` option.

Kernel option
---

If you build
[libcryptoauth](https://github.com/cryptotronix/libcrypti2c) with the
`-DUSE_KERNEL` flag and install the kernel module, this utility will
use that module if you pass in: `-b /dev/atsha0`.

Root
---

You'll need to run as root to access `/dev/i2c*` initially.  You can change this by adding your user to the `i2c` group with:

`sudo usermod -aG i2c user`

Or:

`sudo chmod o+rw /dev/i2c*`


Currently supported commands:

### state
```bash
eclet state
Factory
```

This is the first command you should run and verify it's in the Factory state.  This provides the assurance that the device has not been tampered during transit.

### personalize
```bash
eclet personalize
```

This is the second command you should run.  On success it will not output anything. It configures all slots (0-16) to be holders for P-256 ECC private keys, except slot 8, which is reserved for future use. Keys are not generated at this time. Each key must be individually generated with the `gen-key` command.

***WARNING***

Until you personalize your device, the random number generator will produce a fixed test patterns of FFs and 00s. This is by design. However, it can be a bit suprising to see if you aren't expecting it.

### random
```bash
eclet random
62F95589AC76855A8F9204C9C6B8B85F06E6477D17C3888266AEE8E1CBD65319
```
### serial-num
```bash
eclet serial-num
0123XXXXXXXXXXXXEE
```
X's indicate the unique serial number.

### gen-key
```bash
eclet gen-key
04EED1CB629CF87F8BF6419986F990B92EA3DFA14CDAF70EB3E8DA8F9C9504DBC5B040D6480E88F895E9E1D4477970329B060450C80E1816EFED7B0FA49868CAEB
```

The device will internally create an P-256 ECC key and return the public key. The format of the public key is 0x04 + X + Y. Specify which slot to create a key (0-7, 9-15) with the `-k` option. Currently running this command multiple times will overwrite the public key, see this [issue](https://github.com/cryptotronix/EClet/issues/1).

### sign
```bash
eclet sign -f ChangeLog
3BAEB5705D8765B34B389F1768BAC783FCA786AB64A760D10DD133C86E5892A7A790E424C8E1540551C99FBE4F9F531B504A6004F08F3E0D4E42E96BBDE5C179
```

Performs an ECDSA signature. Data can be specified as a file with the `-f` option or passed via `stdin`. The data will be SHA256 hashed prior to signing. The result is the signature in the format: R + S.

### verify
```bash
eclet verify -f ChangeLog --signature C650D1A30194AD68F60F40C321FB084F6177BEDAC74D0F0C276ED35B00249AC8CF3E96FB7AB14AA48223FBA2E5DD9BCAE232BF963755C42F8FD9BD77FC145D41 --public-key 049B4A517704E16F3C99C6973E29F882EAF840DCD125C725C9552148A74349EB77BECB37AA2DB8056BAF0E236F6DCFEC2C5A9A0F23CEFD8A9DC1F4693718E725D2
```

Verifies an ECDSA signature using the device. You specify the data (which will be SHA256 hashed), the signature (R+S), and the public key (0x04+X+Y). Returns a `0` exit code on success.

### offline-verify-sign
```bash
eclet offline-verify-sign -f ChangeLog --signature C650D1A30194AD68F60F40C321FB084F6177BEDAC74D0F0C276ED35B00249AC8CF3E96FB7AB14AA48223FBA2E5DD9BCAE232BF963755C42F8FD9BD77FC145D41 --public-key 049B4A517704E16F3C99C6973E29F882EAF840DCD125C725C9552148A74349EB77BECB37AA2DB8056BAF0E236F6DCFEC2C5A9A0F23CEFD8A9DC1F4693718E725D2
```

Same as `verify` except it *does not* use the device and can be run on a system with one. It uses the software ECDSA implementation provided by `libcrypti2c`.

Options
---

Options are listed in the `--help` command, but a useful one, if there are issues, is the `-v` option.  This will dump all the data that travels across the I2C bus with the device.

Support
---

IRC: Join the `#cryptotronix` channel on freenode.

Mailing lists: `hashlet-announce` and `hashlet-users` are open for subscriptions [here](https://savannah.nongnu.org/mail/?group=hashlet).

![GPLv3](https://www.gnu.org/graphics/gplv3-127x51.png)
