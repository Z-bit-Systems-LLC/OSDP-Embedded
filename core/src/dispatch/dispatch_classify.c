// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"
#include "osdp/osdp_dispatch.h"
#include "osdp/osdp_replies.h"

osdp_message_kind_t osdp_dispatch_classify(const osdp_frame_t *frame)
{
    if (frame == NULL) {
        return OSDP_MSG_UNKNOWN_COMMAND;
    }

    if (frame->reply) {
        switch (frame->code) {
        case OSDP_REPLY_ACK:       return OSDP_MSG_REPLY_ACK;
        case OSDP_REPLY_NAK:       return OSDP_MSG_REPLY_NAK;
        case OSDP_REPLY_PDID:      return OSDP_MSG_REPLY_PDID;
        case OSDP_REPLY_PDCAP:     return OSDP_MSG_REPLY_PDCAP;
        case OSDP_REPLY_LSTATR:    return OSDP_MSG_REPLY_LSTATR;
        case OSDP_REPLY_ISTATR:    return OSDP_MSG_REPLY_ISTATR;
        case OSDP_REPLY_OSTATR:    return OSDP_MSG_REPLY_OSTATR;
        case OSDP_REPLY_RSTATR:    return OSDP_MSG_REPLY_RSTATR;
        case OSDP_REPLY_RAW:       return OSDP_MSG_REPLY_RAW;
        case OSDP_REPLY_FMT:       return OSDP_MSG_REPLY_FMT;
        case OSDP_REPLY_KEYPAD:    return OSDP_MSG_REPLY_KEYPAD;
        case OSDP_REPLY_COM:       return OSDP_MSG_REPLY_COM;
        case OSDP_REPLY_BIOREADR:  return OSDP_MSG_REPLY_BIOREADR;
        case OSDP_REPLY_BIOMATCHR: return OSDP_MSG_REPLY_BIOMATCHR;
        case OSDP_REPLY_CCRYPT:    return OSDP_MSG_REPLY_CCRYPT;
        case OSDP_REPLY_RMAC_I:    return OSDP_MSG_REPLY_RMAC_I;
        case OSDP_REPLY_BUSY:      return OSDP_MSG_REPLY_BUSY;
        case OSDP_REPLY_FTSTAT:    return OSDP_MSG_REPLY_FTSTAT;
        case OSDP_REPLY_PIVDATAR:  return OSDP_MSG_REPLY_PIVDATAR;
        case OSDP_REPLY_GENAUTHR:  return OSDP_MSG_REPLY_GENAUTHR;
        case OSDP_REPLY_CRAUTHR:   return OSDP_MSG_REPLY_CRAUTHR;
        case OSDP_REPLY_MFGSTATR:  return OSDP_MSG_REPLY_MFGSTATR;
        case OSDP_REPLY_MFGERRR:   return OSDP_MSG_REPLY_MFGERRR;
        case OSDP_REPLY_MFGREP:    return OSDP_MSG_REPLY_MFGREP;
        case OSDP_REPLY_XRD:       return OSDP_MSG_REPLY_XRD;
        default:                   return OSDP_MSG_UNKNOWN_REPLY;
        }
    }

    switch (frame->code) {
    case OSDP_CMD_POLL:         return OSDP_MSG_CMD_POLL;
    case OSDP_CMD_ID:           return OSDP_MSG_CMD_ID;
    case OSDP_CMD_CAP:          return OSDP_MSG_CMD_CAP;
    case OSDP_CMD_LSTAT:        return OSDP_MSG_CMD_LSTAT;
    case OSDP_CMD_ISTAT:        return OSDP_MSG_CMD_ISTAT;
    case OSDP_CMD_OSTAT:        return OSDP_MSG_CMD_OSTAT;
    case OSDP_CMD_RSTAT:        return OSDP_MSG_CMD_RSTAT;
    case OSDP_CMD_OUT:          return OSDP_MSG_CMD_OUT;
    case OSDP_CMD_LED:          return OSDP_MSG_CMD_LED;
    case OSDP_CMD_BUZ:          return OSDP_MSG_CMD_BUZ;
    case OSDP_CMD_TEXT:         return OSDP_MSG_CMD_TEXT;
    case OSDP_CMD_COMSET:       return OSDP_MSG_CMD_COMSET;
    case OSDP_CMD_BIOREAD:      return OSDP_MSG_CMD_BIOREAD;
    case OSDP_CMD_BIOMATCH:     return OSDP_MSG_CMD_BIOMATCH;
    case OSDP_CMD_KEYSET:       return OSDP_MSG_CMD_KEYSET;
    case OSDP_CMD_CHLNG:        return OSDP_MSG_CMD_CHLNG;
    case OSDP_CMD_SCRYPT:       return OSDP_MSG_CMD_SCRYPT;
    case OSDP_CMD_ACURXSIZE:    return OSDP_MSG_CMD_ACURXSIZE;
    case OSDP_CMD_FILETRANSFER: return OSDP_MSG_CMD_FILETRANSFER;
    case OSDP_CMD_MFG:          return OSDP_MSG_CMD_MFG;
    case OSDP_CMD_XWR:          return OSDP_MSG_CMD_XWR;
    case OSDP_CMD_ABORT:        return OSDP_MSG_CMD_ABORT;
    case OSDP_CMD_PIVDATA:      return OSDP_MSG_CMD_PIVDATA;
    case OSDP_CMD_GENAUTH:      return OSDP_MSG_CMD_GENAUTH;
    case OSDP_CMD_CRAUTH:       return OSDP_MSG_CMD_CRAUTH;
    case OSDP_CMD_KEEPACTIVE:   return OSDP_MSG_CMD_KEEPACTIVE;
    default:                    return OSDP_MSG_UNKNOWN_COMMAND;
    }
}

const char *osdp_dispatch_name(osdp_message_kind_t kind)
{
    switch (kind) {
    case OSDP_MSG_UNKNOWN_COMMAND: return "unknown command";
    case OSDP_MSG_UNKNOWN_REPLY:   return "unknown reply";

    case OSDP_MSG_CMD_POLL:        return "osdp_POLL";
    case OSDP_MSG_CMD_ID:          return "osdp_ID";
    case OSDP_MSG_CMD_CAP:         return "osdp_CAP";
    case OSDP_MSG_CMD_LSTAT:       return "osdp_LSTAT";
    case OSDP_MSG_CMD_ISTAT:       return "osdp_ISTAT";
    case OSDP_MSG_CMD_OSTAT:       return "osdp_OSTAT";
    case OSDP_MSG_CMD_RSTAT:       return "osdp_RSTAT";
    case OSDP_MSG_CMD_OUT:         return "osdp_OUT";
    case OSDP_MSG_CMD_LED:         return "osdp_LED";
    case OSDP_MSG_CMD_BUZ:         return "osdp_BUZ";
    case OSDP_MSG_CMD_TEXT:        return "osdp_TEXT";
    case OSDP_MSG_CMD_COMSET:      return "osdp_COMSET";
    case OSDP_MSG_CMD_BIOREAD:     return "osdp_BIOREAD";
    case OSDP_MSG_CMD_BIOMATCH:    return "osdp_BIOMATCH";
    case OSDP_MSG_CMD_KEYSET:      return "osdp_KEYSET";
    case OSDP_MSG_CMD_CHLNG:       return "osdp_CHLNG";
    case OSDP_MSG_CMD_SCRYPT:      return "osdp_SCRYPT";
    case OSDP_MSG_CMD_ACURXSIZE:   return "osdp_ACURXSIZE";
    case OSDP_MSG_CMD_FILETRANSFER:return "osdp_FILETRANSFER";
    case OSDP_MSG_CMD_MFG:         return "osdp_MFG";
    case OSDP_MSG_CMD_XWR:         return "osdp_XWR";
    case OSDP_MSG_CMD_ABORT:       return "osdp_ABORT";
    case OSDP_MSG_CMD_PIVDATA:     return "osdp_PIVDATA";
    case OSDP_MSG_CMD_GENAUTH:     return "osdp_GENAUTH";
    case OSDP_MSG_CMD_CRAUTH:      return "osdp_CRAUTH";
    case OSDP_MSG_CMD_KEEPACTIVE:  return "osdp_KEEPACTIVE";

    case OSDP_MSG_REPLY_ACK:       return "osdp_ACK";
    case OSDP_MSG_REPLY_NAK:       return "osdp_NAK";
    case OSDP_MSG_REPLY_PDID:      return "osdp_PDID";
    case OSDP_MSG_REPLY_PDCAP:     return "osdp_PDCAP";
    case OSDP_MSG_REPLY_LSTATR:    return "osdp_LSTATR";
    case OSDP_MSG_REPLY_ISTATR:    return "osdp_ISTATR";
    case OSDP_MSG_REPLY_OSTATR:    return "osdp_OSTATR";
    case OSDP_MSG_REPLY_RSTATR:    return "osdp_RSTATR";
    case OSDP_MSG_REPLY_RAW:       return "osdp_RAW";
    case OSDP_MSG_REPLY_FMT:       return "osdp_FMT";
    case OSDP_MSG_REPLY_KEYPAD:    return "osdp_KEYPAD";
    case OSDP_MSG_REPLY_COM:       return "osdp_COM";
    case OSDP_MSG_REPLY_BIOREADR:  return "osdp_BIOREADR";
    case OSDP_MSG_REPLY_BIOMATCHR: return "osdp_BIOMATCHR";
    case OSDP_MSG_REPLY_CCRYPT:    return "osdp_CCRYPT";
    case OSDP_MSG_REPLY_RMAC_I:    return "osdp_RMAC_I";
    case OSDP_MSG_REPLY_BUSY:      return "osdp_BUSY";
    case OSDP_MSG_REPLY_FTSTAT:    return "osdp_FTSTAT";
    case OSDP_MSG_REPLY_PIVDATAR:  return "osdp_PIVDATAR";
    case OSDP_MSG_REPLY_GENAUTHR:  return "osdp_GENAUTHR";
    case OSDP_MSG_REPLY_CRAUTHR:   return "osdp_CRAUTHR";
    case OSDP_MSG_REPLY_MFGSTATR:  return "osdp_MFGSTATR";
    case OSDP_MSG_REPLY_MFGERRR:   return "osdp_MFGERRR";
    case OSDP_MSG_REPLY_MFGREP:    return "osdp_MFGREP";
    case OSDP_MSG_REPLY_XRD:       return "osdp_XRD";
    }
    return "unknown";
}
