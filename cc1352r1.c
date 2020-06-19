/*
Wireshark extcap for CC1352r1
CC1352r1 firmware here: https://github.com/HenryGiraldo/sniffer_fw_cc1352r1.git
Copyright(C) 2020, Enrique Giraldo

This program is free software; you can redistribute itand /or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110 - 1301, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#endif

// Serial definitions
#define PING_RETRIES    5
#define PING_RESP_LEN   15
// Parsing definitions
#define CATEGORY_MASK               0xC0
#define COM_RESP_MASK               0x80
// Wireshark definitions
#define DLT_IEEE802_15_4_WITHFCS    195
#define DLT_BLUETOOTH_LE_LL         251
// App definitions
#define BUFF_SIZE                   65536
#define DEBUG                       1
#define FILE_DEBUG                  0

#define ZB_MAX_PAYLOAD              127
#define BLE_MAX_PAYLOAD             250

#if FILE_DEBUG
FILE* debug_file = NULL;
#endif


#if DEBUG
#define DEBUG_PRINT(...) do { fprintf(stdout, __VA_ARGS__ ); } while(0)
#define ERROR_PRINT(...) do { fprintf(stderr, __VA_ARGS__ ); } while(0)
#elif FILE_DEBUG
#define DEBUG_PRINT(...) do { fprintf(debug_file, __VA_ARGS__ ); fflush(debug_file); } while(0)
#define ERROR_PRINT(...) do { fprintf(debug_file, __VA_ARGS__ ); fflush(debug_file); } while(0)
#else
#define DEBUG_PRINT(...) do {} while (0)
#define ERROR_PRINT(...) do {} while (0)
#endif


typedef enum {
    ERR_OK,
    ERR_NO_OK
} err_code;

static const uint8_t bit_reverse_table256[] =
{
  0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
  0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
  0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
  0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
  0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
  0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
  0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
  0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
  0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
  0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
  0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
  0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
  0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
  0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
  0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
  0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
};

static const uint8_t cmd_resp_ok[] = { 0x40, 0x53, 0x80, 0x01, 0x00, 0x00, 0x81, 0x40, 0x45 };

void print_hex_buffer(uint8_t* buffer, int len)
{
#if DEBUG || FILE_DEBUG
    for (int i = 0; i < len; i++)
        DEBUG_PRINT("0x%02x ", buffer[i]);
    DEBUG_PRINT("\n");
#endif
}

static int com_read(HANDLE h_comm, uint8_t *data, int length, int force_wait)
{
    DWORD dwEventMask;                     // Event mask to trigger
    DWORD bytes_read;                     // Bytes read by ReadFile()
    COMSTAT tComStat;
    int i = 0;

    BOOL status = WaitCommEvent(h_comm, &dwEventMask, NULL); //Wait for the character to be received
    // wait  till a character is received
    if (status == FALSE) {
        ERROR_PRINT("WaitCommEvent ERROR\n");
        return ERR_NO_OK;
    }
    else {
        do
        {
            if (!force_wait) {
                if (ClearCommError(h_comm, NULL, &tComStat)) {
                    status = ReadFile(h_comm, data + i, tComStat.cbInQue, &bytes_read, NULL);
                    i += bytes_read;
                }
                else {
                    ERROR_PRINT("ClearCommError failed with error:\n");
                    return ERR_NO_OK;
                }
            }
            else {
                status = ReadFile(h_comm, data + i, length, &bytes_read, NULL);
                i += bytes_read;
            }
        } while (bytes_read > 0);
    }
    return i;
}

BOOL com_write(HANDLE h_comm, int bytes_to_write, uint8_t *wbuffer)
{
    BOOL  status;
    DWORD  bytes_written = 0;          // No of bytes written to the port

    DEBUG_PRINT("\n Writting to COM:\n");
    print_hex_buffer(wbuffer, bytes_to_write);

    status = WriteFile(h_comm,      // Handle to the Serialport
        wbuffer,                    // Data to be written to the port
        bytes_to_write,             // No of bytes to write into the port
        &bytes_written,             // No of bytes written to the port
        NULL);
    return status;
}

/*
The Command and Command Response categories have a 1 byte FCS field after the payload. The FCS value is computed as follows:

Add all bytes in these fields: Packet Info, Packet Length and Payload.
AND the result from step 1 with 0xFF.
*/
uint8_t calc_fcs(uint8_t *frame)
{
    uint8_t fcs_accu = 0;
    int payload_len = frame[3] + (frame[4] << 8);
    int fcs_len = 3 + payload_len;

    for (int i = 0; i < fcs_len; i++) {
        fcs_accu += frame[i + 2];
    }
    /* Is this l-and necessary? */
    return fcs_accu & 0xFF;
}

int get_sub_channel(int channel)
{
    int sub_channel = 5;
    switch (channel % 5)
    {
    case 0:
        sub_channel = 25;
        break;
    case 1:
        sub_channel = 45;
        break;
    case 2:
        sub_channel = 65;
        break;
    case 3:
        sub_channel = 85;
    default:
        break;
    }
    return sub_channel;
}

err_code chan_868_to_freq(int channel, char *freq)
{
    if (channel < 0 || channel > 63)
        return ERR_NO_OK;

    float ref_channel = 863.25;
    float target_channel = ref_channel + (0.2 * channel);

    int primary_channel = (int)target_channel;
    int sub_channel = get_sub_channel(channel) << 16;
    sub_channel = sub_channel / 100;

    freq[0] = (char)primary_channel;
    freq[1] = (char)((primary_channel >> 8) & 0xFF);
    freq[2] = (char)sub_channel;
    freq[3] = (char)((sub_channel >> 8) & 0xFF);

    return ERR_OK;
}

err_code chan_2400_to_freq(int channel, char *freq)
{
    static const int freq_table[16] = {
        2405, 2410, 2415, 2420, 2425, 2430,
        2435, 2440, 2445, 2450, 2455, 2460,
        2465, 2470, 2475, 2480 };

    if (channel < 11 || channel > 26)
        return ERR_NO_OK;

    int target_freq = freq_table[channel - 11];
    freq[0] = (char)target_freq;
    freq[1] = (char)((target_freq >> 8) & 0xFF);

    return ERR_OK;
}

err_code chan_ble1m_to_freq(int channel, char *freq)
{
    static const int freq_table[] = {
        2402, 2426, 2480 };

    if (channel < 37 || channel > 39)
        return ERR_NO_OK;

    int target_freq = freq_table[channel - 37];
    freq[0] = (char)target_freq;
    freq[1] = (char)((target_freq >> 8) & 0xFF);

    return ERR_OK;
}

static err_code get_freq_from_channel(int op_mode, int channel, char *freq)
{
// TODO: refacto with definitions or enums
    if (op_mode == 0)
        return chan_868_to_freq(channel, freq);
    else if (op_mode == 2)
        return chan_ble1m_to_freq(channel, freq);
    else
        return chan_2400_to_freq(channel, freq);
}

static err_code send_cmd(HANDLE h_comm, uint8_t *cmd, int cmd_len)
{
    err_code ret = ERR_OK;
    uint8_t read_buffer[BUFF_SIZE];
    com_write(h_comm, cmd_len, cmd);
    // TODO: Handle command response
    com_read(h_comm, read_buffer, sizeof(cmd_resp_ok), 1);
    print_hex_buffer(read_buffer, sizeof(cmd_resp_ok));
    return ret;
}


void cc1352r1_stop(HANDLE h_comm)
{
    uint8_t read_buffer[BUFF_SIZE];
    uint8_t cmd_stop[] = { 0x40, 0x53, 0x42, 0x00, 0x00, 0x42, 0x40, 0x45 };
    com_write(h_comm, sizeof(cmd_stop), cmd_stop);
    // com_read(h_comm, read_buffer, BUFF_SIZE, 0);  //Cleaning
    com_read(h_comm, read_buffer, sizeof(cmd_stop), 0);  //Cleaning
}

void cc1352r1_reset(HANDLE h_comm)
{
    uint8_t read_buffer[BUFF_SIZE];
    uint8_t cmd_stop[] = { 0x40, 0x53, 0x50, 0x00, 0x00, 0x50, 0x40, 0x45 };
    com_write(h_comm, sizeof(cmd_stop), cmd_stop);
    // com_read(h_comm, read_buffer, BUFF_SIZE, 0);  //Cleaning
    com_read(h_comm, read_buffer, sizeof(cmd_stop), 0);  //Cleaning
    Sleep(200);
}

static err_code cc1352r1_ping(HANDLE h_comm)
{
    err_code ret = ERR_NO_OK;
    uint8_t retries = 0;
    uint8_t read_buffer[PING_RESP_LEN];
    uint8_t cmd_ping[] = { 0x40, 0x53, 0x40, 0x00, 0x00, 0x40, 0x40, 0x45 };
    while (retries <= PING_RETRIES) {
        com_write(h_comm, sizeof(cmd_ping), cmd_ping);
        com_read(h_comm, read_buffer, sizeof(cmd_resp_ok), 1);
        print_hex_buffer(read_buffer, sizeof(cmd_resp_ok));
        if (read_buffer[2] == 0x80 || read_buffer[PING_RESP_LEN - 1] == 0x45) {
            ret = ERR_OK;
            break;
        }
//        cc1352r1_stop(h_comm);
#ifdef _WIN32
        Sleep(500);
#endif
        retries++;
    }
    return ret;
}

static err_code cc1352r1_start(HANDLE h_comm)
{
    char cmd_start[] = { 0x40, 0x53, 0x41, 0x00, 0x00, 0x41, 0x40, 0x45 };
    return send_cmd(h_comm, cmd_start, sizeof(cmd_start));
}

/*  CMD_CFG_PHY
    0x06	IEEE 802.15.4ge(15.4 Stack)	868 and 915 MHz bands
    0x05    BLE - BLE 1 Mbps
    0x04    2.4 GHz band */
static err_code cc1352r1_set_cfg_phy(HANDLE h_comm, int op_band)
{
    /* Predefined frame for 868 */
    uint8_t cmd_set_phy[] = { 0x40, 0x53, 0x47, 0x01, 0x00, 0x06, 0x4E, 0x40, 0x45 };
    /* If we want to operate in 2.4, then modify frame and re-calculate fcs */
    // TODO: Change this magic vars to defininitions.
    if (op_band == 1) {
        cmd_set_phy[5] = 0x04;
        cmd_set_phy[6] = calc_fcs(cmd_set_phy);
    }
    else if (op_band == 2) {
        cmd_set_phy[5] = 0x05;
        cmd_set_phy[6] = calc_fcs(cmd_set_phy);
    }
    return send_cmd(h_comm, cmd_set_phy, sizeof(cmd_set_phy));
}

static err_code cc1352r1_set_channel(HANDLE h_comm, int op_band, int channel)
{
    char cmd_set_channel[] = { 0x40, 0x53, 0x45, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x45 };
    if (get_freq_from_channel(op_band, channel, &cmd_set_channel[5]))
        return ERR_NO_OK;
    cmd_set_channel[9] = calc_fcs(cmd_set_channel);
    return send_cmd(h_comm, cmd_set_channel, sizeof(cmd_set_channel));
}

#if 0
static const uint8_t pn9_table[] = {
  0xff, 0xe1, 0x1d, 0x9a, 0xed, 0x85, 0x33, 0x24,
  0xea, 0x7a, 0xd2, 0x39, 0x70, 0x97, 0x57, 0x0a,
  0x54, 0x7d, 0x2d, 0xd8, 0x6d, 0x0d, 0xba, 0x8f,
  0x67, 0x59, 0xc7, 0xa2, 0xbf, 0x34, 0xca, 0x18,
  0x30, 0x53, 0x93, 0xdf, 0x92, 0xec, 0xa7, 0x15,
  0x8a, 0xdc, 0xf4, 0x86, 0x55, 0x4e, 0x18, 0x21,
  0x40, 0xc4, 0xc4, 0xd5, 0xc6, 0x91, 0x8a, 0xcd,
  0xe7, 0xd1, 0x4e, 0x09, 0x32, 0x17, 0xdf, 0x83,
  0xff, 0xf0, 0x0e, 0xcd, 0xf6, 0xc2, 0x19, 0x12,
  0x75, 0x3d, 0xe9, 0x1c, 0xb8, 0xcb, 0x2b, 0x05,
  0xaa, 0xbe, 0x16, 0xec, 0xb6, 0x06, 0xdd, 0xc7,
  0xb3, 0xac, 0x63, 0xd1, 0x5f, 0x1a, 0x65, 0x0c,
  0x98, 0xa9, 0xc9, 0x6f, 0x49, 0xf6, 0xd3, 0x0a,
  0x45, 0x6e, 0x7a, 0xc3, 0x2a, 0x27, 0x8c, 0x10,
  0x20, 0x62, 0xe2, 0x6a, 0xe3, 0x48, 0xc5, 0xe6,
  0xf3, 0x68, 0xa7, 0x04, 0x99, 0x8b, 0xef, 0xc1,
  0x7f, 0x78, 0x87, 0x66, 0x7b, 0xe1, 0x0c, 0x89,
  0xba, 0x9e, 0x74, 0x0e, 0xdc, 0xe5, 0x95, 0x02,
  0x55, 0x5f, 0x0b, 0x76, 0x5b, 0x83, 0xee, 0xe3,
  0x59, 0xd6, 0xb1, 0xe8, 0x2f, 0x8d, 0x32, 0x06,
  0xcc, 0xd4, 0xe4, 0xb7, 0x24, 0xfb, 0x69, 0x85,
  0x22, 0x37, 0xbd, 0x61, 0x95, 0x13, 0x46, 0x08,
  0x10, 0x31, 0x71, 0xb5, 0x71, 0xa4, 0x62, 0xf3,
  0x79, 0xb4, 0x53, 0x82, 0xcc, 0xc5, 0xf7, 0xe0,
  0x3f, 0xbc, 0x43, 0xb3, 0xbd, 0x70, 0x86, 0x44,
  0x5d, 0x4f, 0x3a, 0x07, 0xee, 0xf2, 0x4a, 0x81,
  0xaa, 0xaf, 0x05, 0xbb, 0xad, 0x41, 0xf7, 0xf1,
  0x2c, 0xeb, 0x58, 0xf4, 0x97, 0x46, 0x19, 0x03,
  0x66, 0x6a, 0xf2, 0x5b, 0x92, 0xfd, 0xb4, 0x42,
  0x91, 0x9b, 0xde, 0xb0, 0xca, 0x09, 0x23, 0x04,
  0x88, 0x98, 0xb8, 0xda, 0x38, 0x52, 0xb1, 0xf9,
  0x3c, 0xda, 0x29, 0x41, 0xe6, 0xe2, 0x7b
};


err_code data_dewhitening(uint8_t* buffer, int buffer_len, int offset)
{
    if (buffer_len > sizeof(pn9_table))
        return ERR_NO_OK;

    for (int i = 0; i < buffer_len; ++i)
        buffer[i] ^= pn9_table[i + offset];

    return ERR_OK;
}

#endif

#define TIMESTAMP_LENGHT                        6
#define SOF_LENGTH                              2
#define PACKET_TYPE_LENGTH                      1
#define PACKET_LEN_LENGTH                       2
#define MAX_PAYLOAD_LENGTH                      2047
#define EOF_LENGTH                              2
#define PACKET_NON_PAYLOAD_LENGTH               (SOF_LENGTH + PACKET_TYPE_LENGTH + PACKET_LEN_LENGTH + EOF_LENGTH)
#define START_OF_FRAME_DELIMITER                0x5340
#define END_OF_FRAME_DELIMITER                  0x4540
#define MAX_ZB_PAYLOAD_LEN                      256 // THIS IS WRONG. it should be 128.

/*
 * Gets a cc1352r1 capture packet from a buffer.
 * The format is defined in SmartRF Packet Sniffer 2
 *
 * Offset  Bytes  Description
 * --------------------------
 * 0       2      Start of Frame Delimiter (value 0x5340)
 * 2       1      Packet Category and Packet Type
 * --------------------------
 * 3       2      Payload length (N)
 * -------------------------------------
 * 5       6      Timestamp
 * 8       N      Payload
 * 8+N-2   1      RSSI
 * 8+N-1   1      status
 -----------------------------------
 * 8+N     1      FCS   OPTIONAL, Frame Check Sequence. This field is only included for Command and Command Response packets.
 * 8+N+1   2      EOF - End of Frame Delimiter (value 0x4540)
 */

#define TI_OVERHEAD_24      TIMESTAMP_LENGHT + 1

// TODO: Unify packet dissection in just a function
static err_code cc1352r1_get_0x04_packet(uint8_t* buffer, int* head, int* tail, int* length)
{
    for (;;) {
        DEBUG_PRINT("HEAD %d, TAIL %d\n", *head, *tail);
        int available = *head - *tail;
        if (*tail > 0) {
            memmove(buffer, buffer + *tail, available);
            *head = available;
            *tail = 0;
        }

        int payload_len = buffer[3] + (buffer[4] << 8);

        if (available) DEBUG_PRINT("\n\n Received frame with payload len %d:\n", payload_len);
        print_hex_buffer(buffer, available);

        if (available < 9) {
            return ERR_NO_OK;
        }

        if (buffer[0] != 0x40 || buffer[1] != 0x53) {
            *head = 0;
            *tail = 0;
            DEBUG_PRINT("Wrong formated frame, discarting\n");
            return ERR_NO_OK;
        }

        if ((buffer[2] & CATEGORY_MASK) != CATEGORY_MASK) {
            if ((buffer[2] & COM_RESP_MASK) == COM_RESP_MASK) {
                *tail = PACKET_NON_PAYLOAD_LENGTH + 1 + payload_len;
                continue;
            }
            else {
                return ERR_NO_OK;
            }
        }

        if (available < PACKET_NON_PAYLOAD_LENGTH + payload_len) {
            DEBUG_PRINT("\n Too small available data\n");
            return ERR_NO_OK;
        }

        *head -= 5 + TI_OVERHEAD_24;                    // start delimiter 2 + packet category 1 + len 2 + timestamp 6 + 1 (Unknown)
        *tail = payload_len - TI_OVERHEAD_24;           // Removing timestamp 6 + 1 (Unknown) and adding End of frame delimiter
        *length = payload_len - (2 + TI_OVERHEAD_24);   // Removing Timestamp (6), 1 Unknown byte and terminator

        if (*length && payload_len <= MAX_ZB_PAYLOAD_LEN) {
            memmove(buffer, buffer + (5 + TI_OVERHEAD_24), *head);
        } else {
            DEBUG_PRINT("\n\n Discarting ZB frame with length %d\n", *length);
            return ERR_NO_OK;
        }

        DEBUG_PRINT("\n\n Writting to PCAPNG, payload_len %d, zb frame length %d:\n", payload_len, *length);
        print_hex_buffer(buffer, *length);

        return ERR_OK;
    }
}

//TODO Figure out why this have 10 octect of overhead
#define BLE_OVERHEAD    10
// TODO: Unify packet dissection in just a function
static err_code cc1352r1_get_0x05_packet(uint8_t* buffer, int* head, int* tail, int* length)
{
    for (;;) {
        DEBUG_PRINT("HEAD %d, TAIL %d\n", *head, *tail);
        int available = *head - *tail;
        if (*tail > 0) {
            memmove(buffer, buffer + *tail, available);
            *head = available;
            *tail = 0;
        }

        int payload_len = buffer[3] + (buffer[4] << 8);

        if (available) DEBUG_PRINT("\n\n Received frame with payload len %d:\n", payload_len);
        print_hex_buffer(buffer, available);

        if (available < 9) {
            return ERR_NO_OK;
        }

        if (buffer[0] != 0x40 || buffer[1] != 0x53) {
            *head = 0;
            *tail = 0;
            DEBUG_PRINT("Wrong formated frame, discarting\n");
            return ERR_NO_OK;
        }

        if ((buffer[2] & CATEGORY_MASK) != CATEGORY_MASK) {
            if ((buffer[2] & COM_RESP_MASK) == COM_RESP_MASK) {
                *tail = PACKET_NON_PAYLOAD_LENGTH + 1 + payload_len;
                continue;
            }
            else {
                return ERR_NO_OK;
            }
        }

        if (available < PACKET_NON_PAYLOAD_LENGTH + payload_len) {
            DEBUG_PRINT("\n Too small available data\n");
            return ERR_NO_OK;
        }

        *head -= 5 + BLE_OVERHEAD;                    // start delimiter 2 + packet category 1 + len 2 + timestamp 6 + 1 (Unknown)
        *tail = payload_len - BLE_OVERHEAD;           // Removing timestamp 6 + 1 (Unknown) and adding End of frame delimiter
        *length = payload_len - (2 + BLE_OVERHEAD);   // Removing Timestamp (6), 1 Unknown byte and terminator

        if (*length && payload_len <= MAX_ZB_PAYLOAD_LEN) {
            memmove(buffer, buffer + (5 + BLE_OVERHEAD), *head);
        }
        else {
            DEBUG_PRINT("\n\n Discarting ZB frame with length %d\n", *length);
            return ERR_NO_OK;
        }

        DEBUG_PRINT("\n\n Writting to PCAPNG, payload_len %d, ble frame length %d:\n", payload_len, *length);
        print_hex_buffer(buffer, *length);

        return ERR_OK;
    }
}

/*
 * Gets a cc1352r1 capture packet from a buffer.
 * The format is defined in SmartRF Packet Sniffer 2
 *
 * Offset  Bytes  Description
 * --------------------------
 * 0       2      Start of Frame Delimiter (value 0x5340)
 * 2       1      Packet Category and Packet Type
 * --------------------------
 * 3       2      Payload length (N)
 * -------------------------------------
 * 5       6      Timestamp
 * 8       N      Payload
 * 8+N-2   1      RSSI
 * 8+N-1   1      status
 -----------------------------------
 * 8+N     1      FCS   OPTIONAL, Frame Check Sequence. This field is only included for Command and Command Response packets.
 * 8+N+1   2      EOF - End of Frame Delimiter (value 0x4540)
 */
 // General host interface packet format

#define TI_OVERHEAD     TIMESTAMP_LENGHT + 2

static err_code cc1352r1_get_0x06_packet(uint8_t* buffer, int* head, int* tail, int* length)
{
    for (;;) {
        DEBUG_PRINT("HEAD %d, TAIL %d\n", *head, *tail);
        int available = *head - *tail;
        if (*tail > 0) {
            memmove(buffer, buffer + *tail, available);
            *head = available;
            *tail = 0;
        }

        int payload_len = buffer[3] + (buffer[4] << 8);

        if (available) DEBUG_PRINT("\n\n Received frame with payload len %d:\n", payload_len);
        print_hex_buffer(buffer, available);

        if (available < 9) {
            return ERR_NO_OK;
        }

        if (buffer[0] != 0x40 || buffer[1] != 0x53) {
            *head = 0;
            *tail = 0;
            DEBUG_PRINT("Wrong formated frame, discarting\n");
            return ERR_NO_OK;
        }

        if ((buffer[2] & CATEGORY_MASK) != CATEGORY_MASK) {
            if ((buffer[2] & COM_RESP_MASK) == COM_RESP_MASK) {
                *tail = PACKET_NON_PAYLOAD_LENGTH + 1 + payload_len;
                continue;
            }
            else {
                return ERR_NO_OK;
            }
        }

        if (available < PACKET_NON_PAYLOAD_LENGTH + payload_len) {
            DEBUG_PRINT("\n Too small available data\n");
            return ERR_NO_OK;
        }

        *tail = payload_len - 2 - TI_OVERHEAD;       /* Removing timestamp 6 + 1 (Unknown) and adding End of frame delimiter */
        *length = payload_len - (2 + TI_OVERHEAD);   /* Removing Timestamp (6), 1 Unknown byte and terminator*/
        *head -= 5 + TI_OVERHEAD; // start delimiter 2 + packet category 1 + len 2

        if (*length && payload_len <= MAX_ZB_PAYLOAD_LEN) {
            memmove(buffer, buffer + (5 + TI_OVERHEAD), *head);
            for (int i = 0; i < *length; i++) {
                buffer[i] = bit_reverse_table256[buffer[i]];
            }
        }
        else {
            DEBUG_PRINT("\n\n Discarting ZB frame with length %d\n", *length);
            return ERR_NO_OK;
        }

        DEBUG_PRINT("\n\n Writting to PCAPNG, payload_len %d, zb frame length %d:\n", payload_len, *length);
        print_hex_buffer(buffer, *length);

        return ERR_OK;
    }
}

/* Header of a PCAP file.
 * https://wiki.wireshark.org/Development/LibpcapFileFormat */

static void cc1352r1_write_pcap_global_header(FILE* file, int op_band)
{
    struct pcap_global_header {
        int magic_number;
        short version_major;
        short version_minor;
        int thiszone;
        int sigfigs;
        int snaplen;
        int network;
    } header = {
        0xa1b2c3d4,  /* byte-order magic number */
        2,           /* version major number */
        4,           /* version minor number */
        0,           /* timezone correction (GMT) */
        0,           /* timestamp accuracy (microseconds) */
        ZB_MAX_PAYLOAD,         /* snapshot length (IEEE 802.15.4 PHY payload max size) */
        DLT_IEEE802_15_4_WITHFCS,         /* network link type (LINKTYPE_IEEE802_15_4_WITHFCS) */
    };
    if (op_band == 2) {
        header.snaplen = BLE_MAX_PAYLOAD;
        header.network = DLT_BLUETOOTH_LE_LL;
    }
    fwrite(&header, sizeof(header), 1, file);
    fflush(file);
}

/*
 * Writes the header of a capture packet.
 */
static void cc1352r1_write_pcap_packet(FILE* file, const void* packet, int length)
{
    struct timeval t;
#ifdef _WIN32
    /* Get the system time as hundreds of nanoseconds since Jan 1 1601 */
    FILETIME ft;
    ULARGE_INTEGER hns;
    GetSystemTimeAsFileTime(&ft);
    hns.LowPart = ft.dwLowDateTime;
    hns.HighPart = ft.dwHighDateTime;
    /* Convert to seconds and microseconds since Jan 1 1970 */
    t.tv_sec = (long)(hns.QuadPart / 10000000 - 11644473600);
    t.tv_usec = (long)(hns.QuadPart / 10 % 1000000);
#else
    gettimeofday(&t, NULL);
#endif
    struct pcap_packet_header {
        int ts_sec;
        int ts_usec;
        int incl_len;
        int orig_len;
    } header = {
      t.tv_sec,   /* timestamp seconds */
      t.tv_usec,  /* timestamp microseconds */
      length,     /* number of bytes of packet data that follow this header */
      length,     /* number of bytes of the packet */
    };
    fwrite(&header, sizeof(header), 1, file);
    fwrite(packet, length, 1, file);
    fflush(file);
}

err_code set_serial_com_timeouts(HANDLE h_comm)
{
    COMMTIMEOUTS timeouts = { 0 };

    timeouts.ReadIntervalTimeout = 10;
    timeouts.ReadTotalTimeoutConstant = 10;
    timeouts.ReadTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = 10;
    timeouts.WriteTotalTimeoutMultiplier = 10;

    if (SetCommTimeouts(h_comm, &timeouts) == FALSE)
        return ERR_NO_OK;
    return ERR_OK;
}

int main(int argc, char *argv[])
{
    int channel = 11;
    int op_band = 1;
    char *fifo = NULL;
    int i;
    char  com_port_name[32];
    char  com_port[100] = "\\\\.\\";  // Name of the Serial port(May Change) to be opened,

    // https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--extcap-interfaces") == 0) {
            puts("extcap {version=0.0.1}\n"
                "interface {value=cc1352r1}{display=TI CC1352R1 802.15.4 packet sniffer}");
            return ERR_OK;
        }
        else if (strcmp(argv[i], "--extcap-config") == 0) {
            puts("arg {number=0}{call=--com_port}{display=Serial Port}{type=string}{COMXX}{required=true}\n"
                "arg {number=1}{call=--op_band}{display=Configure Radio}{type=selector}\n"
                "arg {number=2}{call=--channel}{display=Operation channel (make sure channel exists)}{type=integer}{default=11}{required=true}\n"
                "value {arg=1}{value=0}{display=IEEE 802.15.4g - GFSK 100 Kbps - 868 MHz}\n"
                "value {arg=1}{value=1}{display=IEEE 802.15.4  - O-QPSK - 2.4GHz}\n"
                "value {arg=1}{value=2}{display=BLE - BLE 1 Mbps 2402 MHz}\n");
            return ERR_OK;
        }
        else if (strcmp(argv[i], "--extcap-dlts") == 0) {
            puts("dlt {number=195}{name=cc1352r1}{display=IEEE802_15_4_WITHFCS (TI CC24xx FCS format)}");
            return ERR_OK;
        }
        else if (strcmp(argv[i], "--com_port") == 0) {
#ifdef _WIN32
            strcat(com_port, argv[++i]);
            strcpy(com_port_name, argv[i]);
#else
#endif
        }
        else if (strcmp(argv[i], "--channel") == 0) {
            channel = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--op_band") == 0) {
            op_band = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--fifo") == 0) {
            fifo = argv[++i];
        }
    }

    puts("Usage:\n"
        " cc1352r1 --extcap-interfaces\n"
        " cc1352r1 --extcap-config\n"
        " cc1352r1 --extcap-dlts\n"
        " cc1352r1 --com_port <COMX> --op_band <0/1/2> --channel <valid channel> --fifo <path>\n");

    HANDLE h_comm;                         // Handle to the Serial port
    BOOL  status;                         // status of the various operations


#if FILE_DEBUG
//Replace with your desired path to store debug files
    char str1[256] = "C:\\Users\\user\\Desktop\\1352r1_debug_";
    strcat(str1, com_port_name);
    debug_file = fopen(str1, "a");
    if (debug_file) {
        DEBUG_PRINT("\n ---------------------------------- \n NEW EXECUTION \n \n");
#ifdef _WIN32
        SYSTEMTIME st = { 0 };
        GetSystemTime(&st);
        DEBUG_PRINT("UTC TIME: %02d/%02d/%d - %02d:%02d:%02d\n",
            st.wDay, st.wMonth, st.wYear,
            st.wHour, st.wMinute, st.wSecond);
#endif
    }
    else {
        ERROR_PRINT("\n\Error opening debug file\n");
        return ERR_NO_OK;
    }
#endif // FILE_DEBUG

    DEBUG_PRINT("com_port %s\n", com_port);
    DEBUG_PRINT("op_band %d\n", op_band);
    DEBUG_PRINT("channel %d\n", channel);

    /*---------------------------------- Opening the Serial Port -------------------------------------------*/

    h_comm = CreateFile(com_port,                  // Name of the Port to be Opened
        GENERIC_READ | GENERIC_WRITE, // Read/Write Access
        0,                            // No Sharing, ports cant be shared
        NULL,                         // No Security
        OPEN_EXISTING,                // Open existing port only
        0,                            // Non Overlapped I/O
        NULL);                        // Null for Comm Devices

    if (h_comm == INVALID_HANDLE_VALUE) {
        ERROR_PRINT("\n    Error - Port %s can't be opened\n", com_port);
        return ERR_NO_OK;
    }
    /*------------------------------- Setting the Parameters for the SerialPort ------------------------------*/

    DCB serial_params = { 0 };                         // Initializing DCB structure
    serial_params.DCBlength = sizeof(serial_params);

    status = GetCommState(h_comm, &serial_params);      //retreives  the current settings

    if (status == FALSE)
        ERROR_PRINT("\n    Error! in GetCommState()");

    serial_params.BaudRate = 921600;        // Setting BaudRate = 921600
    serial_params.ByteSize = 8;             // Setting ByteSize = 8
    serial_params.StopBits = ONESTOPBIT;    // Setting StopBits = 1
    serial_params.Parity = NOPARITY;        // Setting Parity = None

    status = SetCommState(h_comm, &serial_params);  //Configuring the port according to settings in DCB

    if (status == FALSE)
    {
        ERROR_PRINT("\n\tFail in setting DCB\n");
        return ERR_NO_OK;
    }

    if (set_serial_com_timeouts(h_comm)) {
        ERROR_PRINT("\n\t    Error setting timeouts");
        return -1;
    }

    //Setting Receive Mask
    status = SetCommMask(h_comm, EV_RXCHAR); //Configure Windows to Monitor the serial device for Character Reception

    if (status == FALSE) {
        ERROR_PRINT("\n\tError setting CommMask\n");
        return ERR_NO_OK;
    }

    /* --------------------------------------- */

    FILE* file = fopen(fifo, "wb");

    if (file)
    {
        cc1352r1_write_pcap_global_header(file, op_band);

        // TODO return errors and handle it.
        cc1352r1_stop(h_comm);
        Sleep(200);

        cc1352r1_reset(h_comm);

        if (cc1352r1_ping(h_comm)) {
            cc1352r1_reset(h_comm);
            Sleep(500);
            if (cc1352r1_ping(h_comm))
                ERROR_PRINT("\n\tCannot init the device\n");
                return ERR_NO_OK;
        }

        cc1352r1_set_cfg_phy(h_comm, op_band);

        if (cc1352r1_set_channel(h_comm, op_band, channel))
            return ERR_NO_OK;

        cc1352r1_start(h_comm);

        err_code (*get_packet[])(uint8_t*, int*, int*, int*) = {
            cc1352r1_get_0x06_packet, cc1352r1_get_0x04_packet, cc1352r1_get_0x05_packet
        };

        uint8_t buffer[BUFF_SIZE];
        int tail = 0;
        int head = 0;

        for (;;)
        {
            int n = com_read(h_comm, buffer + head, sizeof(buffer) - head, 0);
            if (n < 0) {
                ERROR_PRINT("COM READ ERROR HEAD %d, TAIL %d\n", head, tail);
                break;
            }

            head += n;

            int length;
            while (!get_packet[op_band](buffer, &head, &tail, &length))
            {
                cc1352r1_write_pcap_packet(file, buffer, length);
            }
        }
        cc1352r1_stop(h_comm);
    }
    // TODO Close file handlers
    CloseHandle(h_comm);
}
