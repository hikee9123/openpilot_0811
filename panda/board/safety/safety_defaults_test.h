const addr_checks default_rx_checks = {
  .check = NULL,
  .len = 0,
};

int default_rx_hook(CANPacket_t *to_push) {
  UNUSED(to_push);
  return true;
}

// *** no output safety mode ***

static const addr_checks* nooutput_init(int16_t param) {
  UNUSED(param);
  controls_allowed = false;
  relay_malfunction_reset();
  if (current_board->has_obd ) {
    current_board->set_can_mode(CAN_MODE_OBD_CAN2);
    puts("setting can mode obd\n");
  }  
  return &default_rx_checks;
}

static int nooutput_tx_hook(CANPacket_t *to_send) {
  UNUSED(to_send);
  return false;
}

static int nooutput_tx_lin_hook(int lin_num, uint8_t *data, int len) {
  UNUSED(lin_num);
  UNUSED(data);
  UNUSED(len);
  return false;
}

static int default_fwd_hook(int bus_num, CANPacket_t *to_fwd) {
  //UNUSED(bus_num);
  //UNUSED(to_fwd);

  int bus_fwd = -1;
  int addr = GET_ADDR(to_fwd);

  // forward cam to ccan and viceversa, except lkas cmd
  if (bus_num == 0) {
    bus_fwd = 2;
  }
  if (bus_num == 1 ) {
    bus_fwd = 20;
  }  
  if ((bus_num == 2) && (addr != 832) && (addr != 1157)) {  // 832 LKAS11 1157 LFAHDA_MFC
    bus_fwd = 0;
  } 
  return bus_fwd;
}

const safety_hooks nooutput_hooks = {
  .init = nooutput_init,
  .rx = default_rx_hook,
  .tx = nooutput_tx_hook,
  .tx_lin = nooutput_tx_lin_hook,
  .fwd = default_fwd_hook,
};

// *** all output safety mode ***

static const addr_checks* alloutput_init(int16_t param) {
  UNUSED(param);
  controls_allowed = true;
  relay_malfunction_reset();
  return &default_rx_checks;
}

static int alloutput_tx_hook(CANPacket_t *to_send) {
  UNUSED(to_send);
  return true;
}

static int alloutput_tx_lin_hook(int lin_num, uint8_t *data, int len) {
  UNUSED(lin_num);
  UNUSED(data);
  UNUSED(len);
  return true;
}

const safety_hooks alloutput_hooks = {
  .init = alloutput_init,
  .rx = default_rx_hook,
  .tx = alloutput_tx_hook,
  .tx_lin = alloutput_tx_lin_hook,
  .fwd = default_fwd_hook,
};
