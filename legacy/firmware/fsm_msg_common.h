/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2018 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

bool get_features(Features *resp) {
  resp->has_fw_vendor = true;
#if EMULATOR
  strlcpy(resp->fw_vendor, "EMULATOR", sizeof(resp->fw_vendor));
#else
  const image_header *hdr =
      (const image_header *)FLASH_PTR(FLASH_FWHEADER_START);
  // allow both v2 and v3 signatures
  if (SIG_OK == signatures_match(hdr, NULL)) {
    strlcpy(resp->fw_vendor, "SatoshiLabs", sizeof(resp->fw_vendor));
  } else {
    strlcpy(resp->fw_vendor, "UNSAFE, DO NOT USE!", sizeof(resp->fw_vendor));
  }
#endif
  resp->has_vendor = true;
  strlcpy(resp->vendor, "trezor.io", sizeof(resp->vendor));
  resp->major_version = VERSION_MAJOR;
  resp->minor_version = VERSION_MINOR;
  resp->patch_version = VERSION_PATCH;
  resp->has_device_id = true;
  strlcpy(resp->device_id, config_uuid_str, sizeof(resp->device_id));
  resp->has_pin_protection = true;
  resp->pin_protection = config_hasPin();
  resp->has_passphrase_protection = true;
  config_getPassphraseProtection(&(resp->passphrase_protection));
#ifdef SCM_REVISION
  int len = sizeof(SCM_REVISION) - 1;
  resp->has_revision = true;
  memcpy(resp->revision.bytes, SCM_REVISION, len);
  resp->revision.size = len;
#endif
  resp->has_bootloader_hash = true;
  resp->bootloader_hash.size =
      memory_bootloader_hash(resp->bootloader_hash.bytes);

  resp->has_language =
      config_getLanguage(resp->language, sizeof(resp->language));
  resp->has_label = config_getLabel(resp->label, sizeof(resp->label));
  resp->has_initialized = true;
  resp->initialized = config_isInitialized();
  resp->has_imported = config_getImported(&(resp->imported));
  resp->has_unlocked = true;
  resp->unlocked = session_isUnlocked();
  resp->has_backup_availability = true;
  bool needs_backup = false;
  config_getNeedsBackup(&needs_backup);
  resp->backup_availability = needs_backup ? BackupAvailability_Required
                                           : BackupAvailability_NotAvailable;
  resp->has_unfinished_backup = true;
  config_getUnfinishedBackup(&(resp->unfinished_backup));
  resp->has_no_backup = true;
  config_getNoBackup(&(resp->no_backup));
  resp->has_flags = config_getFlags(&(resp->flags));
  resp->has_model = true;
  strlcpy(resp->model, "1", sizeof(resp->model));
  resp->has_safety_checks = true;
  resp->safety_checks = config_getSafetyCheckLevel();
  resp->has_busy = true;
  resp->busy = (system_millis_busy_deadline > timer_ms());
  if (session_isUnlocked()) {
    resp->has_wipe_code_protection = true;
    resp->wipe_code_protection = config_hasWipeCode();
    resp->has_auto_lock_delay_ms = true;
    resp->auto_lock_delay_ms = config_getAutoLockDelayMs();
  }

#if BITCOIN_ONLY
  resp->capabilities_count = 2;
  resp->capabilities[0] = Capability_Capability_Bitcoin;
  resp->capabilities[1] = Capability_Capability_Crypto;
#else
  resp->capabilities_count = 8;
  resp->capabilities[0] = Capability_Capability_Bitcoin;
  resp->capabilities[1] = Capability_Capability_Bitcoin_like;
  resp->capabilities[2] = Capability_Capability_Crypto;
  resp->capabilities[3] = Capability_Capability_Ethereum;
  resp->capabilities[4] = Capability_Capability_NEM;
  resp->capabilities[5] = Capability_Capability_Stellar;
  resp->capabilities[6] = Capability_Capability_U2F;
  resp->capabilities[7] = Capability_Capability_MimbleWimbleCoin;
#endif
  return resp;
}

void fsm_msgInitialize(const Initialize *msg) {
  fsm_abortWorkflows();

  uint8_t *session_id;
  if (msg && msg->has_session_id) {
    session_id = session_startSession(msg->session_id.bytes);
  } else {
    session_id = session_startSession(NULL);
  }

  RESP_INIT(Features);
  get_features(resp);

  resp->has_session_id = true;
  memcpy(resp->session_id.bytes, session_id, sizeof(resp->session_id.bytes));
  resp->session_id.size = sizeof(resp->session_id.bytes);

  layoutHome();
  msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgGetFeatures(const GetFeatures *msg) {
  (void)msg;
  RESP_INIT(Features);
  get_features(resp);
  msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgPing(const Ping *msg) {
  RESP_INIT(Success);

  if (msg->has_button_protection && msg->button_protection) {
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                      _("Do you really want to"), _("answer to ping?"), NULL,
                      NULL, NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (msg->has_message) {
    resp->has_message = true;
    memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
  }
  msg_write(MessageType_MessageType_Success, resp);
  layoutHome();
}

void fsm_msgChangePin(const ChangePin *msg) {
  CHECK_INITIALIZED

  bool removal = msg->has_remove && msg->remove;
  if (removal) {
    if (config_hasPin()) {
      layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                        _("Do you really want to"), _("remove current PIN?"),
                        NULL, NULL, NULL, NULL);
    } else {
      fsm_sendSuccess(_("PIN removed"));
      return;
    }
  } else {
    if (config_hasPin()) {
      layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                        _("Do you really want to"), _("change current PIN?"),
                        NULL, NULL, NULL, NULL);
    } else {
      layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                        _("Do you really want to"), _("set new PIN?"), NULL,
                        NULL, NULL, NULL);
    }
  }
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (protectChangePin(removal)) {
    if (removal) {
      fsm_sendSuccess(_("PIN removed"));
    } else {
      fsm_sendSuccess(_("PIN changed"));
    }
  }

  layoutHome();
}

void fsm_msgChangeWipeCode(const ChangeWipeCode *msg) {
  CHECK_INITIALIZED

  bool removal = msg->has_remove && msg->remove;
  bool has_wipe_code = config_hasWipeCode();

  if (removal) {
    // Note that if storage is locked, then config_hasWipeCode() returns false.
    if (has_wipe_code || !session_isUnlocked()) {
      layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                        _("Do you really want to"), _("disable wipe code"),
                        _("protection?"), NULL, NULL, NULL);
    } else {
      fsm_sendSuccess(_("Wipe code removed"));
      return;
    }
  } else {
    if (has_wipe_code) {
      layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                        _("Do you really want to"), _("change the current"),
                        _("wipe code?"), NULL, NULL, NULL);
    } else {
      layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                        _("Do you really want to"), _("set a new wipe code?"),
                        NULL, NULL, NULL, NULL);
    }
  }
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (protectChangeWipeCode(removal)) {
    if (removal) {
      fsm_sendSuccess(_("Wipe code removed"));
    } else if (has_wipe_code) {
      fsm_sendSuccess(_("Wipe code changed"));
    } else {
      fsm_sendSuccess(_("Wipe code set"));
    }
  }

  layoutHome();
}

void fsm_msgWipeDevice(const WipeDevice *msg) {
  (void)msg;
  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                    _("Do you really want to"), _("wipe the device?"), NULL,
                    _("All data will be lost."), NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_WipeDevice, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  config_wipe();
  // the following does not work on Mac anyway :-/ Linux/Windows are fine, so it
  // is not needed usbReconnect(); // force re-enumeration because of the serial
  // number change
  fsm_sendSuccess(_("Device wiped"));
  layoutHome();
}

void fsm_msgGetEntropy(const GetEntropy *msg) {
  CHECK_PIN

#if !DEBUG_RNG
  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                    _("Do you really want to"), _("send entropy?"), NULL, NULL,
                    NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
#endif
  RESP_INIT(Entropy);
  uint32_t len = msg->size;
  if (len > 1024) {
    len = 1024;
  }
  resp->entropy.size = len;
  random_buffer(resp->entropy.bytes, len);
  msg_write(MessageType_MessageType_Entropy, resp);
  layoutHome();
}

#if DEBUG_LINK

void fsm_msgLoadDevice(const LoadDevice *msg) {
  CHECK_PIN

  CHECK_NOT_INITIALIZED

  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("I take the risk"), NULL,
                    _("Loading private seed"), _("is not recommended."),
                    _("Continue only if you"), _("know what you are"),
                    _("doing!"), NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (msg->mnemonics_count && !(msg->has_skip_checksum && msg->skip_checksum)) {
    if (!mnemonic_check(msg->mnemonics[0])) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      _("Mnemonic with wrong checksum provided"));
      layoutHome();
      return;
    }
  }

  config_loadDevice(msg);
  fsm_sendSuccess(_("Device loaded"));
  layoutHome();
}

#endif

void fsm_msgResetDevice(const ResetDevice *msg) {
  CHECK_PIN

  CHECK_NOT_INITIALIZED

  CHECK_PARAM(!msg->has_strength || msg->strength == 128 ||
                  msg->strength == 192 || msg->strength == 256,
              _("Invalid seed strength"));

  fsm_abortWorkflows();

  reset_init(msg->has_strength ? msg->strength : 128,
             msg->has_passphrase_protection && msg->passphrase_protection,
             msg->has_pin_protection && msg->pin_protection,
             msg->has_language ? msg->language : 0,
             msg->has_label ? msg->label : 0,
             msg->has_u2f_counter ? msg->u2f_counter : 0,
             msg->has_skip_backup ? msg->skip_backup : false,
             msg->has_no_backup ? msg->no_backup : false,
             msg->has_entropy_check ? msg->entropy_check : false);
}

void fsm_msgEntropyAck(const EntropyAck *msg) {
  reset_entropy(msg->entropy.bytes, msg->entropy.size);
}

void fsm_msgEntropyCheckContinue(const EntropyCheckContinue *msg) {
  reset_continue(msg->has_finish ? msg->finish : false);
}

void fsm_msgBackupDevice(const BackupDevice *msg) {
  (void)msg;

  CHECK_INITIALIZED

  CHECK_PIN_UNCACHED

  char mnemonic[MAX_MNEMONIC_LEN + 1];
  if (config_getMnemonic(mnemonic, sizeof(mnemonic))) {
    reset_backup(true, mnemonic);
  }
  memzero(mnemonic, sizeof(mnemonic));
}

void fsm_msgCancel(const Cancel *msg) {
  (void)msg;
  fsm_abortWorkflows();
  fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
}

void fsm_msgLockDevice(const LockDevice *msg) {
  (void)msg;
  config_lockDevice();
  layoutScreensaver();
  fsm_sendSuccess(_("Session cleared"));
}

void fsm_msgEndSession(const EndSession *msg) {
  (void)msg;
  session_endCurrentSession();
  fsm_sendSuccess(_("Session ended"));
}

void fsm_msgApplySettings(const ApplySettings *msg) {
  CHECK_PARAM(
      !msg->has_passphrase_always_on_device,
      _("This firmware is incapable of passphrase entry on the device."));

  CHECK_PARAM(msg->has_label || msg->has_language || msg->has_use_passphrase ||
                  msg->has_homescreen || msg->has_auto_lock_delay_ms ||
                  msg->has_safety_checks,
              _("No setting provided"));

  CHECK_PIN

  if (msg->has_label) {
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                      _("Do you really want to"), _("change name to"),
                      msg->label, "?", NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }
  if (msg->has_language) {
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                      _("Do you really want to"), _("change language to"),
                      msg->language, "?", NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }
  if (msg->has_use_passphrase) {
    layoutDialogSwipe(
        &bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
        _("Do you really want to"),
        msg->use_passphrase ? _("enable passphrase") : _("disable passphrase"),
        _("protection?"), NULL, NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }
  if (msg->has_homescreen) {
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                      _("Do you really want to"), _("change the home"),
                      _("screen?"), NULL, NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (msg->has_auto_lock_delay_ms) {
    if (msg->auto_lock_delay_ms < MIN_AUTOLOCK_DELAY_MS) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      _("Auto-lock delay too short"));
      layoutHome();
      return;
    }
    if (msg->auto_lock_delay_ms > MAX_AUTOLOCK_DELAY_MS) {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      _("Auto-lock delay too long"));
      layoutHome();
      return;
    }
    layoutConfirmAutoLockDelay(msg->auto_lock_delay_ms);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (msg->has_safety_checks) {
    if (msg->safety_checks == SafetyCheckLevel_Strict ||
        msg->safety_checks == SafetyCheckLevel_PromptTemporarily) {
      layoutConfirmSafetyChecks(msg->safety_checks);
      if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      _("Unsupported safety-checks setting"));
      layoutHome();
      return;
    }
  }

  if (msg->has_label) {
    config_setLabel(msg->label);
  }
  if (msg->has_language) {
    config_setLanguage(msg->language);
  }
  if (msg->has_use_passphrase) {
    config_setPassphraseProtection(msg->use_passphrase);
  }
  if (msg->has_homescreen) {
    config_setHomescreen(msg->homescreen.bytes, msg->homescreen.size);
  }
  if (msg->has_auto_lock_delay_ms) {
    config_setAutoLockDelayMs(msg->auto_lock_delay_ms);
  }
  if (msg->has_safety_checks) {
    config_setSafetyCheckLevel(msg->safety_checks);
  }
  fsm_sendSuccess(_("Settings applied"));
  layoutHome();
}

void fsm_msgApplyFlags(const ApplyFlags *msg) {
  CHECK_PIN

  config_applyFlags(msg->flags);
  fsm_sendSuccess(_("Flags applied"));
}

void fsm_msgRecoveryDevice(const RecoveryDevice *msg) {
  CHECK_PIN_UNCACHED

  CHECK_PARAM(msg->type == RecoveryType_NormalRecovery ||
                  msg->type == RecoveryType_DryRun,
              _("UnlockRepeatedBackup not supported"))

  fsm_abortWorkflows();

  const bool dry_run = msg->has_type ? msg->type == RecoveryType_DryRun : false;
  if (!dry_run) {
    CHECK_NOT_INITIALIZED
  } else {
    CHECK_INITIALIZED
    CHECK_PARAM(!msg->has_passphrase_protection && !msg->has_pin_protection &&
                    !msg->has_language && !msg->has_label &&
                    !msg->has_u2f_counter,
                _("Forbidden field set in dry-run"))
  }

  CHECK_PARAM(!msg->has_word_count || msg->word_count == 12 ||
                  msg->word_count == 18 || msg->word_count == 24,
              _("Invalid word count"));

  recovery_init(msg->has_word_count ? msg->word_count : 12,
                msg->has_passphrase_protection && msg->passphrase_protection,
                msg->has_pin_protection && msg->pin_protection,
                msg->has_language ? msg->language : 0,
                msg->has_label ? msg->label : 0,
                msg->has_enforce_wordlist && msg->enforce_wordlist,
                msg->has_input_method ? msg->input_method : 0,
                msg->has_u2f_counter ? msg->u2f_counter : 0, dry_run);
}

void fsm_msgWordAck(const WordAck *msg) {
  CHECK_UNLOCKED

  recovery_word(msg->word);
}

void fsm_msgSetU2FCounter(const SetU2FCounter *msg) {
  CHECK_PIN

  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                    _("Do you want to set"), _("the U2F counter?"), NULL, NULL,
                    NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  config_setU2FCounter(msg->u2f_counter);
  fsm_sendSuccess(_("U2F counter set"));
  layoutHome();
}

void fsm_msgGetNextU2FCounter(void) {
  CHECK_PIN

  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                    _("Do you want to"), _("increase and retrieve"),
                    _("the U2F counter?"), NULL, NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  uint32_t counter = config_nextU2FCounter();

  RESP_INIT(NextU2FCounter);
  resp->u2f_counter = counter;
  msg_write(MessageType_MessageType_NextU2FCounter, resp);
  layoutHome();
}

static void progress_callback(uint32_t iter, uint32_t total) {
  layoutProgress(_("Please wait"), 1000 * iter / total);
}

void fsm_msgGetFirmwareHash(const GetFirmwareHash *msg) {
  RESP_INIT(FirmwareHash);
  layoutProgressSwipe(_("Please wait"), 0);
  if (memory_firmware_hash(msg->challenge.bytes, msg->challenge.size,
                           progress_callback, resp->hash.bytes) != 0) {
    fsm_sendFailure(FailureType_Failure_FirmwareError, NULL);
    return;
  }

  resp->hash.size = sizeof(resp->hash.bytes);
  msg_write(MessageType_MessageType_FirmwareHash, resp);
  layoutHome();
}

void fsm_msgSetBusy(const SetBusy *msg) {
  if (msg->has_expiry_ms) {
    system_millis_busy_deadline = timer_ms() + msg->expiry_ms;
  } else {
    system_millis_busy_deadline = 0;
  }
  fsm_sendSuccess(NULL);
  layoutHome();
  return;
}
