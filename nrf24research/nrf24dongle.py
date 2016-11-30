'''
  Copyright (C) 2016 Bastille Networks

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import sys
import time
import usb
import logging

# Check pyusb dependency
try:
    from usb import core as _usb_core
except ImportError, ex:
    print '''
------------------------------------------
| PyUSB was not found or is out of date. |
------------------------------------------

Please update PyUSB using pip:

sudo pip install -U -I pip && sudo pip install -U -I pyusb
'''
    sys.exit(1)

# USB commands
TRANSMIT_PAYLOAD = 0x04
ENTER_SNIFFER_MODE = 0x05
ENTER_PROMISCUOUS_MODE = 0x06
ENTER_TONE_TEST_MODE = 0x07
TRANSMIT_ACK_PAYLOAD = 0x08
SET_CHANNEL = 0x09
GET_CHANNEL = 0x0A
ENABLE_LNA_PA = 0x0B
TRANSMIT_PAYLOAD_GENERIC = 0x0C
ENTER_PROMISCUOUS_MODE_GENERIC = 0x0D
RECEIVE_PAYLOAD = 0x12

# nRF24LU1+ registers
RF_CH = 0x05

# RF data rates
RF_RATE_250K = 0
RF_RATE_1M = 1
RF_RATE_2M = 2


def parse_prefix_address(address):
    # Parse the prefix addresses
    prefix_address = address.replace(':', '').decode('hex')
    if len(prefix_address) > 5:
        raise Exception('Invalid prefix address: {0}'.format(address))

def addr2str(address):
    ':'.join(address.encode('hex'))


# Setup logging
level = logging.DEBUG if verbose else logging.INFO
logging.basicConfig(level=level, format='[%(asctime)s.%(msecs)03d]  %(message)s', datefmt="%Y-%m-%d %H:%M:%S")


# nRF24LU1+ radio dongle
class nrf24:
    # Sufficiently long timeout for use in a VM
    usb_timeout = 2500

    # Constructor
    def __init__(self, index=0, vid=0x1915, pid=0x0102, ):
        try:
            self.dongle = list(usb.core.find(idVendor=vid, idProduct=pid, find_all=True))[index]
            self.dongle.set_configuration()
        except usb.core.USBError, ex:
            raise ex
        except:
            raise Exception('Cannot find USB dongle.')

    # Put the radio in pseudo-promiscuous mode
    def enter_promiscuous_mode(self, prefix=[]):
        self.send_usb_command(ENTER_PROMISCUOUS_MODE, [len(prefix)] + map(ord, prefix))
        self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)
        if len(prefix) > 0:
            logging.debug('Entered promiscuous mode with address prefix {0}'.
                          format(':'.join('{:02X}'.format(ord(b)) for b in prefix)))
        else:
            logging.debug('Entered promiscuous mode')

    # Put the radio in pseudo-promiscuous mode without CRC checking
    def enter_promiscuous_mode_generic(self, prefix=[], rate=RF_RATE_2M, payload_length=32):
        self.send_usb_command(ENTER_PROMISCUOUS_MODE_GENERIC, [len(prefix), rate, payload_length] + map(ord, prefix))
        self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)
        if len(prefix) > 0:
            logging.debug('Entered generic promiscuous mode with address prefix {0}'.
                          format(':'.join('{:02X}'.format(ord(b)) for b in prefix)))
        else:
            logging.debug('Entered promiscuous mode')

    # Put the radio in ESB "sniffer" mode (ESB mode w/o auto-acking)
    def enter_sniffer_mode(self, address):
        self.send_usb_command(ENTER_SNIFFER_MODE, [len(address)] + map(ord, address))
        self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)
        logging.debug('Entered sniffer mode with address {0}'.
                      format(':'.join('{:02X}'.format(ord(b)) for b in address[::-1])))

    # Put the radio into continuous tone (TX) test mode
    def enter_tone_test_mode(self, channel=None):
        if channel is not None:
            self.set_channel(channel)

        self.send_usb_command(ENTER_TONE_TEST_MODE, [])
        self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)
        logging.debug('Entered continuous tone test mode')

    # Receive a payload if one is available
    def receive_payload(self):
        self.send_usb_command(RECEIVE_PAYLOAD, ())
        return self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)

    # Transmit a generic (non-ESB) payload
    def transmit_payload_generic(self, payload, address="\x33\x33\x33\x33\x33"):
        data = [len(payload), len(address)] + map(ord, payload) + map(ord, address)
        self.send_usb_command(TRANSMIT_PAYLOAD_GENERIC, data)
        return self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)[0] > 0

    # Transmit an ESB payload
    def transmit_payload(self, payload, timeout=4, retransmits=15):
        data = [len(payload), timeout, retransmits] + map(ord, payload)
        self.send_usb_command(TRANSMIT_PAYLOAD, data)
        return self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)[0] > 0

    # Transmit an ESB ACK payload
    def transmit_ack_payload(self, payload):
        data = [len(payload)] + map(ord, payload)
        self.send_usb_command(TRANSMIT_ACK_PAYLOAD, data)
        return self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)[0] > 0

    # Set the RF channel
    def set_channel(self, channel):
        if channel > 125: channel = 125
        self.send_usb_command(SET_CHANNEL, [channel])
        self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)
        logging.debug('Tuned to {0}'.format(channel))

    # Get the current RF channel
    def get_channel(self):
        self.send_usb_command(GET_CHANNEL, [])
        return self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)

    # Enable the LNA (CrazyRadio PA)
    def enable_lna(self):
        logging.debug("Enabling LNA")
        self.send_usb_command(ENABLE_LNA_PA, [])
        self.dongle.read(0x81, 64, timeout=nrf24.usb_timeout)

    # Send a USB command
    def send_usb_command(self, request, data):
        data = [request] + list(data)
        self.dongle.write(0x01, data, timeout=nrf24.usb_timeout)

    def sniff(self, address, timeout=100/1000, ack_timeout=250/1000, retries=1, ping_payload=0x0f0f0f0f, channels=range(2, 84)):
        # Put the radio in sniffer mode (ESB w/o auto ACKs)
        self.enter_sniffer_mode(address)

        # Format the ACK timeout and auto retry values
        ack_timeout = int(ack_timeout / 250) - 1
        ack_timeout = max(0, min(ack_timeout, 15))
        retries = max(0, min(retries, 15))

        # Sweep through the channels and decode ESB packets in pseudo-promiscuous mode
        last_ping = time.time()
        channel_index = 0
        while True:

            # Follow the target device if it changes channels
            if time.time() - last_ping > timeout:

                # First try pinging on the active channel
                if not self.transmit_payload(ping_payload, ack_timeout, retries):

                    # Ping failed on the active channel, so sweep through all available channels
                    success = False
                    for channel_index in range(len(channels)):
                        self.set_channel(channels[channel_index])
                        if self.transmit_payload(ping_payload, ack_timeout, retries):
                            # Ping successful, exit out of the ping sweep
                            last_ping = time.time()
                            logging.debug('Ping success on channel {0}'.format(channels[channel_index]))
                            success = True
                            break

                    # Ping sweep failed
                    if not success:
                        logging.debug('Unable to ping {0}'.format(addr2str(address)))

                # Ping succeeded on the active channel
                else:
                    logging.debug('Ping success on channel {0}'.format(channels[channel_index]))
                    last_ping = time.time()

            # Receive payloads
            value = self.receive_payload()
            if value[0] == 0:
                # Reset the channel timer
                last_ping = time.time()

                # Split the payload from the status byte
                payload = value[1:]

                # Log the packet
                logging.info('{0: >2}  {1: >2}  {2}  {3}'.format(
                    channels[channel_index],
                    len(payload),
                    addr2str(address),
                    ':'.join('{:02X}'.format(b) for b in payload)))
