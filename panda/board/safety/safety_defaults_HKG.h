bool HKG_forward_bus2 = true;
int HKG_LKAS_bus0_cnt = 0;

const addr_checks default_rx_checks = {
  .check = NULL,
  .len = 0,
};

int default_rx_hook(CANPacket_t *to_push) {
  int bus = GET_BUS(to_push);
  int addr = GET_ADDR(to_push);

  if (addr == 832) {  // LKAS11(832)
    if (bus == 0) { 
      HKG_LKAS_bus0_cnt = 10; 
      if (HKG_forward_bus2) 
      {
        HKG_forward_bus2 = false; 
        puts("  LKAS on bus0: forwarding disabled\n");
      }
    }
    if (bus == 2) {
      if (HKG_LKAS_bus0_cnt > 0) 
      {
        HKG_LKAS_bus0_cnt--;
      } 
      else if (!HKG_forward_bus2) 
      {
        HKG_forward_bus2 = true; 
        puts("  LKAS on bus2 & not on bus0: forwarding enabled\n");
      }
    }
  }

  return true;
}

// *** no output safety mode ***

static const addr_checks* nooutput_init(int16_t param) {
  UNUSED(param);
  controls_allowed = false;
  relay_malfunction_reset();
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
  UNUSED(to_fwd);
  int bus_fwd = -1;

  if( HKG_forward_bus2 )
  {
    if (bus_num == 0 ) {
      bus_fwd = 2;
    }
    //int addr = GET_ADDR(to_fwd);
    //if (bus_num == 2 && (addr != 832) && (addr != 1157) ) {
    if (bus_num == 2 ) {
      bus_fwd =  0;
    }
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