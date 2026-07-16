`ifndef KB_FWD_ENG_SCOREBOARD_SV
`define KB_FWD_ENG_SCOREBOARD_SV

// Import the external AXI package type definitions
//import com_axi_pkg::*;
import kb_cxl_pkg::*;
import DenaliSvCdn_axi::*;


class kb_fwd_eng_scoreboard extends uvm_component;
  `uvm_component_utils(kb_fwd_eng_scoreboard)

  // AXI fifos
  kb_axi4_analysis_fifo exp_fifo;
  kb_axi4_analysis_fifo act_fifo;
  
  kb_axi4_analysis_fifo address_fifo;
  kb_axi4_analysis_fifo w_fifo;
  kb_axi4_analysis_fifo resp_fifo;


  // CXL fifos -- per-lane decoded items
  uvm_tlm_analysis_fifo #(kb_cxl_mon_item) cxl_m2s_req_fifo;
  uvm_tlm_analysis_fifo #(kb_cxl_mon_item) cxl_m2s_rwd_fifo;
  uvm_tlm_analysis_fifo #(kb_cxl_mon_item) cxl_s2m_drc_fifo;
  uvm_tlm_analysis_fifo #(kb_cxl_mon_item) cxl_s2m_ndr_fifo;

  // CXL bus snapshot fifo -- one entry per active cycle, full bus state
  uvm_tlm_analysis_fifo #(kb_cxl_bus_snap) cxl_m2s_bus_fifo;
  
  uvm_tlm_analysis_fifo #(denaliCdn_apbTransaction) apb_fifo;
  
  kb_fwd_eng_env_cfg h_env_cfg;
  
  //fe_top_mm h_regblock;
  
  // PERSISTENT CREDIT TRACKERS 
  int exp_req_credits[KB_CXL_MAX_NUM_REQ];
  int exp_rwd_credits[KB_CXL_MAX_NUM_RWD];
  int exp_s2m_ndr_credits[KB_CXL_MAX_NUM_NDR];
  int exp_s2m_drc_credits[KB_CXL_MAX_NUM_DRC];  

  localparam int MAX_CREDITS_PER_LANE = 32;
  localparam bit [1:0] BURST = 2'd1;

  // Trackers storing verified byte addresses for scoreboard matching
  bit [63:0] q[$];
  bit [63:0] rwd_q[$];


// =========================================================================
  // APB LOCAL CONFIGURATION SHADOW REGISTERS
  // =========================================================================
  
  // Decoder APB Storage Arrays (10 instances, 32-bit registers)
  bit [31:0] r_base_low[10];
  bit [31:0] r_base_high[10];
  bit [31:0] r_size_low[10];
  bit [31:0] r_size_high[10];
  bit [31:0] r_skip_low[10];
  bit [31:0] r_skip_high[10];

  // Computed 64-bit Hardware Boundaries
  bit [63:0] hdm_hpa_base[10];
  bit [63:0] hdm_hpa_top[10];
  bit [63:0] hdm_dpa_base[10];
  bit hdm_committed[10]; 

  // Global Read (RD) Configuration Registers (32-bit)
  bit [31:0] rd_max_burst_rate_inst;
  bit [31:0] rd_cm_ratio_inst;
  bit [31:0] rd_current_token_inst;
  bit [31:0] rd_reset_token;

  // Global Write (WR) Configuration Registers (32-bit)
  bit [31:0] wr_max_burst_rate_inst;
  bit [31:0] wr_cm_ratio_inst;
  bit [31:0] wr_current_token_inst;
  bit [31:0] wr_reset_token;

  // INTERNAL TOKEN BUCKET STATE
  bit [31:0] internal_rd_tokens;
  bit [31:0] internal_wr_tokens;
  
  // Constant defined by the spec
  const bit [31:0] TRANSMIT_TOKEN = 32'h1; // 1 << 16
 
  bit [45:0] calculated_la;  

  // =========================================================================
  // ADDRESS MAPPER LUT (Split into MSB and LSB Arrays)
  // Total Size: 512KB -> 65,536 64-bit words
  // =========================================================================
  bit [31:0] address_map_lut     [65536]; // MSB Data
  bit [31:0] lsb_address_map_lut [65536]; // LSB Data

  typedef struct {
    bit [45:0]   hpa;
    bit [1023:0] data; 
    bit [127:0]  byte_enable; 
    bit [3:0]    opcode;
    bit [32:0]   tag;
    bit          poison;
    bit [55:0]   dpa;   // is this 36 bit sor 44 bits ???
    bit [5:0]    target;
    bit          invalidated;
    bit [1:0]    qos;
  } EGRS_IN;

  // Egress Tracking Repositories
  EGRS_IN egress_write_q[$];
  EGRS_IN egress_read_q[$];

  // Write request channel source 
  typedef struct packed {
    bit         valid;
    bit [7:0]   id;      
    bit [63:0]  addr;    
    bit [7:0]   len;     
    bit [7:0]   size;    
    bit [1:0]   burst;   
    bit [3:0]   qos;     
    bit [127:0] user;    
  } axi_aw_src_t;

  // Write data channel source 
  typedef struct packed {
    bit          valid;
    bit [1023:0] data;   
    bit [127:0]  strb;   
    bit          last;
    bit [127:0]  user;   
  } axi_w1024_src_t;

  // Read request channel source 
  typedef struct packed {
    bit         valid;
    bit [7:0]   id;      
    bit [63:0]  addr;    
    bit [7:0]   len;     
    bit [7:0]   size;    // Custom integrated field
    bit [1:0]   burst;   
    bit [3:0]   qos;     
    bit [127:0] user;    
  } axi_ar_src_t;

  // --- Downstream AXI Tracking Queues (Using local struct types) ---
  axi_aw_src_t    aw_queue[$];
  axi_w1024_src_t w_queue[$];
  axi_ar_src_t    ar_queue[$];


  // =========================================================================
  // INGRESS STRUCTS & QUEUES
  // =========================================================================

  // --- Downstream AXI Response Capture Structs ---
  // Write response channel source (B Channel)
  typedef struct packed {
    bit         valid;
    bit [7:0]   id;     
    bit [1:0]   resp;   
    bit [127:0] user;   
  } axi_b_src_t;

  // Read data channel source (R Channel - Flattened for 1024-bit)
  typedef struct packed {
    bit          valid;
    bit [7:0]    id;
    bit [1023:0] data;   
    bit [1:0]    resp;
    bit          last;
    bit [127:0]  user;   
  } axi_r1024_src_t;

  // --- Egress to Ingress Context Trackers ---
  // Enhanced tracking structure to preserve DPA alignment for read responses
  typedef struct {
    bit [32:0] tag;
    bit [45:0] hpa;
  } r_track_t;

  // --- Tagtable queues ---
  r_track_t  tag_table_read_q[$];   // Read Tag Table
  bit [32:0] tag_table_write_q[$];  // Write Tag Table 

  // --- Expected CXL Completion Structs (Perfect 64B slices) ---
  typedef struct {
    bit [15:0]  s2m_tag;
    bit [511:0] s2m_data;
    bit         s2m_poison;
  } exp_cxl_drc_t;

  typedef struct {
    bit [15:0] s2m_tag;
    bit [1:0]  s2m_status; 
  } exp_cxl_ndr_t;

  // Expected CXL Completion Queues
  exp_cxl_drc_t exp_drc_q[$];
  exp_cxl_ndr_t exp_ndr_q[$];
  bit rate_limit_sync_backdoor;

// Shadow Memory indexed by the 46-bit HPA
  bit [511:0] shadow_mem [bit [45:0]]; 
  
  extern function new(string name="kb_fwd_eng_scoreboard", uvm_component parent=null);
  extern function void build_phase(uvm_phase phase);
  extern task run_phase(uvm_phase phase);


  extern function void check_128b_boundaries(input bit [399:0] req_bus);  
  extern function void check_rwd_680b_boundaries(input logic [1359:0] rwd_bus);
  
  extern function bit predict_hpa_base_resolve(input bit [45:0] incoming_hpa, input string txn_type);

  extern function bit [45:0] predict_la_resolve(input bit [45:0] hpa, int matching_idx);
  extern function void convert_egress_to_axi(); 
  extern task compare_egress_axi_traffic();
  extern function axi_aw_src_t convert_denali_to_aw(kb_axi4_vendor_txn_t txn);
  extern function axi_ar_src_t convert_denali_to_ar(kb_axi4_vendor_txn_t txn);
  extern function axi_w1024_src_t convert_denali_to_w(kb_axi4_vendor_txn_t txn);
  extern function axi_b_src_t convert_denali_to_b(kb_axi4_vendor_txn_t txn);
  extern function axi_r1024_src_t convert_denali_to_r(kb_axi4_vendor_txn_t txn);
  extern task process_s2m_ndr_traffic();
  extern task process_s2m_drc_traffic();
  extern task process_apb_traffic();
  extern task get_apb_config_data(bit [63:0] addr, bit [31:0] data);  
  extern function void update_hdm_calculations(); 
  extern function void calculate_rate_limits(kb_cxl_bus_snap snap);
`ifdef KB_USE_BACKDOOR_CFG
  extern task sync_lut_from_ral();
  extern function void sync_cfg_from_ral_backdoor();
  extern function void sync_rates_from_ral_backdoor();  
`endif
endclass : kb_fwd_eng_scoreboard

function kb_fwd_eng_scoreboard::new(string name="kb_fwd_eng_scoreboard", uvm_component parent=null);
  super.new(name, parent);
endfunction : new

function void kb_fwd_eng_scoreboard::build_phase(uvm_phase phase);
  super.build_phase(phase);
  address_fifo  = kb_axi4_analysis_fifo::type_id::create("address_fifo", this);
  w_fifo        = kb_axi4_analysis_fifo::type_id::create("w_fifo", this);
  resp_fifo     = kb_axi4_analysis_fifo::type_id::create("resp_fifo", this);
  cxl_m2s_bus_fifo = new("cxl_m2s_bus_fifo", this); 
  cxl_m2s_req_fifo = new("cxl_m2s_req_fifo", this);
  cxl_m2s_rwd_fifo = new("cxl_m2s_rwd_fifo", this);
  cxl_s2m_drc_fifo = new("cxl_s2m_drc_fifo", this);
  cxl_s2m_ndr_fifo = new("cxl_s2m_ndr_fifo", this);
  act_fifo = new("act_fifo", this); 
  apb_fifo = new("apb_fifo", this); 

  if(!uvm_config_db#(kb_fwd_eng_env_cfg)::get(this, "", "env_cfg", h_env_cfg))
    `uvm_fatal(get_type_name(), "FATAL ERROR: Failed to get 'env_cfg' from config DB!")
  hdm_committed='{10{1}};

endfunction : build_phase



task kb_fwd_eng_scoreboard::run_phase(uvm_phase phase);
  kb_cxl_bus_snap m2s_snap; 
  bit first_traffic_seen = 1'b0;
  
  // Traffic Flags
  bit has_m2s_traffic;
  bit has_s2m_traffic;

  // M2S Per-Cycle Counters
  int req_tx_count, rwd_tx_count, req_crd_rx_count, rwd_crd_rx_count; // TODO: might have to change to 4 bits to use this index based for lanes(can also continue with int aswell)

  // S2M Per-Cycle Counters
  int s2m_ndr_tx_count, s2m_drc_tx_count, s2m_ndr_crd_rx_count, s2m_drc_crd_rx_count;

  `uvm_info(get_type_name(), "Scoreboard active. Waiting for CXL link initialization...", UVM_LOW)
  fork
    compare_egress_axi_traffic();
    process_s2m_drc_traffic();
    process_s2m_ndr_traffic();   
  
    // FRONTDOOR: Only launch the APB monitor thread if backdoor is NOT defined
  
    `ifndef KB_USE_BACKDOOR_CFG
      process_apb_traffic();      
    `endif    
  join_none

  forever begin
    
    // Reset ALL per-cycle flags at the start of the cycle
    has_m2s_traffic      = 1'b0;
    has_s2m_traffic      = 1'b0;
    req_tx_count         = 0;
    rwd_tx_count         = 0;
    req_crd_rx_count     = 0;
    rwd_crd_rx_count     = 0;
    s2m_ndr_tx_count     = 0;
    s2m_drc_tx_count     = 0;
    s2m_ndr_crd_rx_count = 0;
    s2m_drc_crd_rx_count = 0;

    cxl_m2s_bus_fifo.get(m2s_snap);

`ifdef KB_USE_BACKDOOR_CFG

    sync_rates_from_ral_backdoor();
    if(|wr_max_burst_rate_inst & !rate_limit_sync_backdoor)begin
      `uvm_info(get_type_name(),$sformatf("[backdoor_rate_limiter] wr_max_burst_rate_inst=0x%0h ",wr_max_burst_rate_inst),UVM_HIGH)
      rate_limit_sync_backdoor=1; // to control multiple prints after ratelimiter is configured
      // if ratelimiter is configured dynamically local regs sync with those values but this print cannot be seen
    end

`endif //KB_USE_BACKDOOR_CFG

    // TOKEN BUCKET RATE LIMITER
    calculate_rate_limits(m2s_snap);

    // =========================================================================
    // CHANNEL 1: M2S (Host-to-Device) Logic
    // =========================================================================
    if (m2s_snap.rst_n == 1'b0 || m2s_snap.mst_ack == 1'b0) begin
      // M2S Link is DOWN. Flush all per-lane M2S credits.
      `uvm_info(get_type_name(), "M2S ACK (mst_ack) deasserted. Resetting per-lane M2S credits.", UVM_MEDIUM)
      
      foreach(exp_req_credits[i]) exp_req_credits[i] = 0;
      foreach(exp_rwd_credits[i]) exp_rwd_credits[i] = 0;
      
      first_traffic_seen = 1'b0; // RAL sync must happen again when link recovers
    end    
    else begin
      // M2S Link is UP. Do Math on a per-lane basis.
      
      // --- REQ Lane Processing ---
      for (int lane = 0; lane < KB_CXL_MAX_NUM_REQ; lane++) begin
        // Accumulate Lane Credit
        if (m2s_snap.m2s_req_crd[lane]) begin
          req_crd_rx_count++; // Keep for noise filter
          exp_req_credits[lane]++;
        end
        
        // Consume Lane Credit
        if (m2s_snap.m2s_req[lane * KB_CXL_REQ_SIZE] == 1'b1) begin
          has_m2s_traffic = 1'b1;
          req_tx_count++; // Keep for noise filter
          exp_req_credits[lane]--;
        end

        // Per-Lane Boundary Checkers
        if (exp_req_credits[lane] < 0)
          `uvm_error(get_type_name(), $sformatf("[CREDIT_ERR] REQ Underflow on Lane %0d! Count: %0d", lane, exp_req_credits[lane]))
        if (exp_req_credits[lane] > MAX_CREDITS_PER_LANE)
          `uvm_error(get_type_name(), $sformatf("[CREDIT_ERR] REQ Overflow on Lane %0d! Count: %0d", lane, exp_req_credits[lane]))
      end

      // --- RWD Lane Processing ---
      for (int lane = 0; lane < KB_CXL_MAX_NUM_RWD; lane++) begin
        // Accumulate Lane Credit
        if (m2s_snap.m2s_rwd_crd[lane]) begin
          rwd_crd_rx_count++; 
          exp_rwd_credits[lane]++;
        end
        
        // Consume Lane Credit
        if (m2s_snap.m2s_rwd[lane * KB_CXL_RWD_SIZE] == 1'b1) begin
          has_m2s_traffic = 1'b1;
          rwd_tx_count++; 
          exp_rwd_credits[lane]--;
        end

        // Per-Lane Boundary Checkers
        if (exp_rwd_credits[lane] < 0)
          `uvm_error(get_type_name(), $sformatf("[CREDIT_ERR] RWD Underflow on Lane %0d! Count: %0d", lane, exp_rwd_credits[lane]))
        if (exp_rwd_credits[lane] > MAX_CREDITS_PER_LANE)
          `uvm_error(get_type_name(), $sformatf("[CREDIT_ERR] RWD Overflow on Lane %0d! Count: %0d", lane, exp_rwd_credits[lane]))
      end
    end

    // =========================================================================
    // CHANNEL 2: S2M (Device-to-Host) Logic
    // =========================================================================
    if (m2s_snap.rst_n == 1'b0 || m2s_snap.slv_ack == 1'b0) begin
      // S2M Link is DOWN. Flush S2M credits for ALL lanes.
      `uvm_info(get_type_name(), "S2M ACK (slv_ack) deasserted. Resetting per-lane S2M credits.", UVM_MEDIUM)
      
      foreach (exp_s2m_ndr_credits[i]) exp_s2m_ndr_credits[i] = 0;
      foreach (exp_s2m_drc_credits[i]) exp_s2m_drc_credits[i] = 0;
    end 
    else begin
      // S2M Link is UP. Do Per-Lane Math.
      
      // --- NDR CHANNEL ---
      for (int lane = 0; lane < KB_CXL_MAX_NUM_NDR; lane++) begin
        // Increment on credit received for THIS lane
        if (m2s_snap.s2m_ndr_crd[lane]) begin
          exp_s2m_ndr_credits[lane]++;
        end
        
        // Decrement on valid transmission on THIS lane
        if (m2s_snap.s2m_ndr[lane * KB_CXL_NDR_SIZE] == 1'b1) begin
          has_s2m_traffic = 1'b1;
          exp_s2m_ndr_credits[lane]--;
        end

        // Strict Underflow/Overflow checks per lane
        if (exp_s2m_ndr_credits[lane] < 0)
          `uvm_error(get_type_name(), $sformatf("S2M NDR Credit Underflow on Lane %0d! Count: %0d", lane, exp_s2m_ndr_credits[lane]))
        if (exp_s2m_ndr_credits[lane] > MAX_CREDITS_PER_LANE)
          `uvm_error(get_type_name(), $sformatf("S2M NDR Credit Overflow on Lane %0d! Count hit maximum threshold of %0d", lane, exp_s2m_ndr_credits[lane]))
      end

      // --- DRC CHANNEL ---
      for (int lane = 0; lane < KB_CXL_MAX_NUM_DRC; lane++) begin
        // Increment on credit received for THIS lane
        if (m2s_snap.s2m_drc_crd[lane]) begin
          exp_s2m_drc_credits[lane]++;
        end
        
        // Decrement on valid transmission on THIS lane
        if (m2s_snap.s2m_drc[lane * KB_CXL_DRC_SIZE] == 1'b1) begin
          has_s2m_traffic = 1'b1;
          exp_s2m_drc_credits[lane]--;
        end

        // Strict Underflow/Overflow checks per lane
        if (exp_s2m_drc_credits[lane] < 0)
          `uvm_error(get_type_name(), $sformatf("S2M DRC Credit Underflow on Lane %0d! Count: %0d", lane, exp_s2m_drc_credits[lane]))
        if (exp_s2m_drc_credits[lane] > MAX_CREDITS_PER_LANE)
          `uvm_error(get_type_name(), $sformatf("S2M DRC Credit Overflow on Lane %0d! Count hit maximum threshold of %0d", lane, exp_s2m_drc_credits[lane]))
      end
    end

    // =========================================================================
    // STEP 3: THE NOISE FILTER (Only skip if the ENTIRE bus is dead)
    // =========================================================================
    if (!has_m2s_traffic && !has_s2m_traffic && 
        m2s_snap.m2s_req_crd == 0 && m2s_snap.m2s_rwd_crd == 0 &&
        m2s_snap.s2m_ndr_crd == 0 && m2s_snap.s2m_drc_crd == 0) begin
      continue; 
    end

    // =========================================================================
    // STEP 4: ROUTE TRAFFIC TO THE CORRECT CHECKERS
    // =========================================================================
    
    // --- M2S Dedicated Processing Zone ---
    if (has_m2s_traffic) begin//{
      if (!first_traffic_seen) begin

`ifdef KB_USE_BACKDOOR_CFG
        // Execute backdoor pull
        sync_cfg_from_ral_backdoor();
        sync_lut_from_ral();
        `uvm_info(get_type_name(), "[BACKDOOR_SCB] Successfully synced HDM Decoders from Register Model", UVM_LOW)
`else
        // Frontdoor relies on process_apb_traffic() which has already been running
        `uvm_info(get_type_name(), "[FRONTDOOR_SCB] HDM Decoders configured dynamically via APB VIP Monitor", UVM_LOW)
`endif
                  
        foreach(hdm_hpa_top[i]) begin
          // Optional safety check: only print if the decoder actually has a size configured            
            `uvm_info(get_type_name(), $sformatf("Synced Dec %0d | FULL HPA: 0x%0h to 0x%0h | HPA [51:28]: 0x%0h to 0x%0h | DPA Base: 0x%0h", 
                  i, hdm_hpa_base[i], hdm_hpa_top[i],hdm_hpa_base[i][51:28], hdm_hpa_top[i][51:28], hdm_dpa_base[i]), UVM_HIGH)
        end
        
        first_traffic_seen = 1'b1;
      end
      
      check_128b_boundaries(m2s_snap.m2s_req);
      check_rwd_680b_boundaries(m2s_snap.m2s_rwd);
    end//}
    
    convert_egress_to_axi(); //irrespective of has_m2s_traffic this needs to check continuously


    // --- S2M Dedicated Processing Zone ---
//    if (has_s2m_traffic) begin
      // S2M Checks go here
//    end


    // =========================================================================
    // STEP 5: DYNAMIC CREDIT TRACKER (Prints only on active cycle)
    // =========================================================================
    // Trigger print if any traffic was sent OR any credit was received this cycle
    if (has_m2s_traffic || has_s2m_traffic || 
        (|m2s_snap.m2s_req_crd) || (|m2s_snap.m2s_rwd_crd) ||
        (|m2s_snap.s2m_ndr_crd) || (|m2s_snap.s2m_drc_crd)) begin
        
        `uvm_info(get_type_name(), 
          $sformatf("[CREDITS] M2S Bank (REQ: %p, RWD: %p) | S2M Bank (NDR: %p, DRC: %p)", 
                    exp_req_credits, exp_rwd_credits, 
                    exp_s2m_ndr_credits, exp_s2m_drc_credits), 
          UVM_HIGH)
    end

  end
endtask : run_phase


function void kb_fwd_eng_scoreboard::check_128b_boundaries(
  input bit [399:0] req_bus // 4 lanes * 100 bits
);
  bit [63:0] channel_addr[4]; 
  bit [3:0]  opcode[4];
  bit [2:0]  snptype[4];
  bit [1:0]  metafield[4];
  bit [15:0] tag_extracted[4];

  bit [3:0]  ch_active;
  bit [3:0]  qualified_active = 4'b0000;
  bit [3:0]  processed = 4'b0000;
  bit        is_128b_aligned;
  bit        is_contiguous;
  
  EGRS_IN req_tx; 

  for (int i = 0; i < 4; i++) begin
    int base = i * KB_CXL_REQ_SIZE; // Using macro

    // Extract the valid bit directly from the lane's LSB
    ch_active[i] = req_bus[base];

    if (ch_active[i]) begin
      // Replaced hardcoded numbers with package macros
      opcode[i]           = req_bus[base+1  + KB_CXL_OPCODE_OFF   +: KB_CXL_OPCODE_W];  
      snptype[i]          = req_bus[base+1  + KB_CXL_SNP_OFF      +: KB_CXL_SNP_W];  
      metafield[i]        = req_bus[base+1  + KB_CXL_META_FLD_OFF +: KB_CXL_META_FLD_W];  
      tag_extracted[i]    = req_bus[base+1  + KB_CXL_TAG_OFF      +: KB_CXL_TAG_WIDTH]; 
      channel_addr[i]     = req_bus[base+1  + KB_CXL_HPA_OFF      +: KB_CXL_ADDR_BW]; 
      
      if ((opcode[i] == 4'h1) && (snptype[i] == 3'b000) && (metafield[i] == 2'b11)) begin 
        qualified_active[i] = 1'b1;            
      end            
      else begin                
        // Error completion queue push for unintended protocol headers                
        `uvm_warning(get_type_name(), $sformatf("[REQ_ERR] Unintended protocol fields on Ch %0d. Opcode:%0h Snp:%0h Meta:%0h", i, opcode[i], snptype[i], metafield[i]))
        // TODO: error_completion_queue.push_back(error_tx);            
      end
    end
  end

  for (int i = 0; i < 4; i++) begin
    if (!qualified_active[i] || processed[i]) continue;

    req_tx = '{default: '0};

    if ((i < 3) && qualified_active[i+1] && !processed[i+1]) begin
      is_128b_aligned = (channel_addr[i][0]  == 1'b0);
      is_contiguous   = (channel_addr[i+1] == (channel_addr[i] + 1));

      if (is_128b_aligned && is_contiguous) begin
        `uvm_info(get_type_name(), $sformatf("[REQ_SB] Detected 128B Aligned Pair Ch %0d-%0d at Addr: 0x%0h", i, i+1, channel_addr[i]), UVM_MEDIUM)
        q.push_back(channel_addr[i]);  // not just for reference        
        
        if (predict_hpa_base_resolve(channel_addr[i][45:0], "REQ")) begin
          // Get the 16-bit Index and pull the LUT entry
          bit [15:0] lut_idx   = calculated_la[37:22];
          bit [28:0] lut_entry = address_map_lut[lut_idx];
          
          if(lut_entry[27] == 1'b0)begin
            `uvm_error("LUT_PERM_FAULT", $sformatf("Read attempted at LA 0x%0h but read_ena is 0 at index %0d", calculated_la, lut_idx))              
            // TODO: error_completion_queue.push_back(error_tx);            
          end  
          else begin
            req_tx.opcode = opcode[i];
            req_tx.hpa    = channel_addr[i][45:0];            
            req_tx.dpa    = {lut_entry[26:0], calculated_la[21:0],6'd0}; 
            req_tx.poison = 1'b0; 
            
            req_tx.tag[15:0]  = tag_extracted[i];
            req_tx.tag[31:16] = tag_extracted[i+1];
            req_tx.tag[32]    = 1'b1; 
            
            egress_read_q.push_back(req_tx);
   
            `uvm_info(get_type_name(), $sformatf("[QUEUE_PUSH] Pushed to Egress Read Q. Current Queue Depth: %0d\n   Struct EGRS_IN {\n     opcode : 0x%0h\n     la     : 0x%0h\n     dpa    : 0x%0h\n     tag    : 0x%0h\n     poison : %0b\n     be     : 0x%0h\n     data   : 0x%0h\n   }", egress_read_q.size(), req_tx.opcode, calculated_la, req_tx.dpa, req_tx.tag, req_tx.poison, req_tx.byte_enable, req_tx.data), UVM_HIGH)
          end
        end
        else begin
          // Route HDM decode failure
          // TODO: error_completion_queue.push_back(error_tx);
        end

        processed[i]   = 1'b1;
        processed[i+1] = 1'b1;
        continue; 
      end
    end

    `uvm_info(get_type_name(), $sformatf("[REQ_SB] Detected Standalone 64B Transaction Ch %0d at Addr: 0x%0h", i, channel_addr[i]), UVM_HIGH)
    q.push_back(channel_addr[i]);
    
    if (predict_hpa_base_resolve(channel_addr[i][45:0], "REQ")) begin
      // Get the 16-bit Index and pull the LUT entry
      bit [15:0] lut_idx   = calculated_la[37:22];
      bit [28:0] lut_entry = address_map_lut[lut_idx];
      
      if(lut_entry[27] == 1'b0)begin
        `uvm_error("LUT_PERM_FAULT", $sformatf("Read attempted at LA 0x%0h but read_ena is 0 at index %0d", calculated_la, lut_idx))              
        // TODO: error_completion_queue.push_back(error_tx);
      end
      else begin
        req_tx.opcode     = opcode[i];
        req_tx.hpa        = channel_addr[i][45:0];        
        req_tx.dpa        = {lut_entry[26:0],calculated_la[21:0],6'd0}; 
        req_tx.poison     = 1'b0; 
        req_tx.tag[15:0]  = tag_extracted[i];
        req_tx.tag[31:16] = '0;
        req_tx.tag[32]    = 1'b0; 
        
        egress_read_q.push_back(req_tx);    
        `uvm_info(get_type_name(), $sformatf("[QUEUE_PUSH] Pushed to Egress Read Q. Current Queue Depth: %0d\n   Struct EGRS_IN {\n     opcode : 0x%0h\n     la     : 0x%0h\n     dpa    : 0x%0h\n     tag    : 0x%0h\n     poison : %0b\n     be     : 0x%0h\n     data   : 0x%0h\n   }", egress_read_q.size(), req_tx.opcode, calculated_la, req_tx.dpa, req_tx.tag, req_tx.poison, req_tx.byte_enable, req_tx.data), UVM_HIGH)
      end
    end
    else begin
      // Route HDM decode failure
      // TODO: error_completion_queue.push_back(error_tx);
    end
    processed[i] = 1'b1;
  end
endfunction:check_128b_boundaries

function void kb_fwd_eng_scoreboard::check_rwd_680b_boundaries(
  input logic [1359:0] rwd_bus // 2 lanes * 680 bits inline
);
  bit [63:0]  rwd_addr_bytes[2];  
  bit [3:0]   opcode[2];
  bit [2:0]   snptype[2];
  bit [1:0]   metafield[2];
  bit [15:0]  tag_extracted[2];
  bit         poison_extracted[2];
  bit [511:0] data_payload[2];
  bit [63:0]  be_payload[2];

  bit [1:0]   ch_active;   
  bit [1:0]   qualified_active = 2'b00;
  bit [1:0]   processed = 2'b00;
  bit         is_128b_aligned;
  bit         is_contiguous;
  
  EGRS_IN rwd_tx; 

  for (int i = 0; i < 2; i++) begin
    int lane_base = i * KB_CXL_RWD_SIZE; // Using macro
    
    // Set dynamic offsets using the package macros  
    int hdr_base  = lane_base + 1;
    int be_base   = lane_base + KB_CXL_RWD_BE_OFF;
    int data_base = lane_base + KB_CXL_RWD_DATA_OFF;        

    // Extract valid bit from the LSB of the current 680-bit chunk 
    ch_active[i] = rwd_bus[lane_base];    
      
    if (ch_active[i]) begin
      // Slicing the Header utilizing macro definitions  
      opcode[i]           = rwd_bus[hdr_base + KB_CXL_OPCODE_OFF   +: KB_CXL_OPCODE_W];    
      snptype[i]          = rwd_bus[hdr_base + KB_CXL_SNP_OFF      +: KB_CXL_SNP_W];    
      metafield[i]        = rwd_bus[hdr_base + KB_CXL_META_FLD_OFF +: KB_CXL_META_FLD_W];  
      tag_extracted[i]    = rwd_bus[hdr_base + KB_CXL_TAG_OFF      +: KB_CXL_TAG_WIDTH]; 
      rwd_addr_bytes[i]   = rwd_bus[hdr_base + KB_CXL_HPA_OFF      +: KB_CXL_ADDR_BW]; 
      poison_extracted[i] = rwd_bus[hdr_base + KB_CXL_POISON_OFF]; // Removed the hardcoded +73
      
      // Slicing the BE and Data using the macro offsets            
      be_payload[i]       = rwd_bus[be_base   +: KB_CXL_RWD_BE_SIZE]; 
      data_payload[i]     = rwd_bus[data_base +: KB_CXL_RWD_DATA_SIZE];

      if ((opcode[i] == 4'h1) && (snptype[i] == 3'b000) && (metafield[i] == 2'b11)) begin
        qualified_active[i] = 1'b1;
      end
      else begin
        // Error completion queue push for unintended protocol headers
        `uvm_warning(get_type_name(), $sformatf("[RWD_ERR] Unintended protocol fields on Ch %0d. Opcode:%0h Snp:%0h Meta:%0h", i, opcode[i], snptype[i], metafield[i]))
        // TODO: error_completion_queue.push_back(error_tx);
      end
    end
  end

  for (int i = 0; i < 2; i++) begin
    if (!qualified_active[i] || processed[i]) continue;  

    rwd_tx = '{default: '0};

    if ((i < 1) && qualified_active[i+1] && !processed[i+1]) begin
      is_128b_aligned = (rwd_addr_bytes[i][0]  == 1'b0);
      is_contiguous   = (rwd_addr_bytes[i+1] == (rwd_addr_bytes[i] + 1));

      if (is_128b_aligned && is_contiguous) begin
        `uvm_info(get_type_name(), $sformatf("[RWD_SB] Detected 128B Aligned Rwd Pair Ch 0-1 at Addr: 0x%0h", rwd_addr_bytes[i]), UVM_MEDIUM)
        rwd_q.push_back(rwd_addr_bytes[i]); 
        
        // ----- hpa region check
        if (predict_hpa_base_resolve(rwd_addr_bytes[i][45:0], "RWD")) begin
          // Get the 16-bit Index and pull the LUT entry
          bit [15:0] lut_idx   = calculated_la[37:22];
          bit [28:0] lut_entry = address_map_lut[lut_idx];
          $display("LUT INDEX %0d LUT Entry[26:0] 0x%0h LUT_ENTRY 0x%0h",lut_idx,lut_entry[26:0],address_map_lut[lut_idx]);
          if(lut_entry[28] == 1'b0)begin
            `uvm_error("LUT_PERM_FAULT", $sformatf("Write attempted at LA 0x%0h but wr_ena is 0 at index %0d", calculated_la, lut_idx))
            // TODO: error_completion_queue.push_back(error_tx);
          end
          else begin
            rwd_tx.opcode = opcode[i];
            rwd_tx.dpa    = {lut_entry[26:0], calculated_la[21:0],6'd0};
            rwd_tx.poison = poison_extracted[i] | poison_extracted[i+1]; 
            
            rwd_tx.data[511:0]         = data_payload[i];      
            rwd_tx.data[1023:512]      = data_payload[i+1];   
            rwd_tx.byte_enable[63:0]   = be_payload[i];
            rwd_tx.byte_enable[127:64] = be_payload[i+1];
            
            rwd_tx.tag[15:0]  = tag_extracted[i];
            rwd_tx.tag[31:16] = tag_extracted[i+1];
            rwd_tx.tag[32]    = 1'b1; 

            shadow_mem[rwd_addr_bytes[i]]   = data_payload[i];      // Lower 64B
            shadow_mem[rwd_addr_bytes[i+1]] = data_payload[i+1];    // Upper 64B  

            egress_write_q.push_back(rwd_tx);
            `uvm_info(get_type_name(), $sformatf("[QUEUE_PUSH] Pushed to Egress Write Q. Current Queue Depth: %0d\n   Struct EGRS_IN {\n     opcode : 0x%0h\n     la     : 0x%0h\n     dpa    : 0x%0h\n     tag    : 0x%0h\n     poison : %0b\n     be     : 0x%0x\n     data   : 0x%0x\n   }", egress_write_q.size(), rwd_tx.opcode, calculated_la, rwd_tx.dpa, rwd_tx.tag, rwd_tx.poison, rwd_tx.byte_enable, rwd_tx.data), UVM_HIGH)

          end
        end
        else begin
          // Route HDM decode failure
          // TODO: error_completion_queue.push_back(error_tx);
        end
        processed[i]   = 1'b1;
        processed[i+1] = 1'b1;
        continue; 
      end
    end

`uvm_info(get_type_name(), $sformatf("[RWD_SB] Detected Standalone 64B Rwd Transaction Ch %0d at Addr: 0x%0h. Alignment: %s", 
    i, 
    rwd_addr_bytes[i], 
    (rwd_addr_bytes[i][0] == 1'b0) ? "128B ALIGNED (Lower)" : "64B ALIGNED (Upper)"
), UVM_HIGH)
    rwd_q.push_back(rwd_addr_bytes[i]);
            
    if (predict_hpa_base_resolve(rwd_addr_bytes[i][45:0], "RWD")) begin                           
      // Get the 16-bit Index and pull the LUT entry
      bit [15:0] lut_idx   = calculated_la[37:22];
      bit [28:0] lut_entry = address_map_lut[lut_idx];
      $display("LUT INDEX %0d LUT Entry[26:0] %0d LUT_ENTRY %0d",lut_idx,lut_entry[26:0],address_map_lut[lut_idx]);
      if(lut_entry[28] == 1'b0)begin
        `uvm_error("LUT_PERM_FAULT", $sformatf("Write attempted at LA 0x%0h but wr_ena is 0 at index %0d", calculated_la, lut_idx))
        // TODO: error_completion_queue.push_back(error_tx);            
      end
      else begin
        rwd_tx.opcode = opcode[i];
        rwd_tx.dpa    = {lut_entry[26:0], calculated_la[21:0],6'd0};
        rwd_tx.poison = poison_extracted[i]; 
        
        if (rwd_addr_bytes[i][0] == 1'b0) begin
          // Target is lower 64B aligned (Offset 0x00)
          rwd_tx.data[511:0]         = data_payload[i];
          rwd_tx.data[1023:512]      = '0;
          rwd_tx.byte_enable[63:0]   = be_payload[i];
          rwd_tx.byte_enable[127:64] = '0;
        end
        else begin
          // Target is upper 64B aligned (Offset 0x40)
          rwd_tx.data[511:0]         = '0;
          rwd_tx.data[1023:512]      = data_payload[i];
          rwd_tx.byte_enable[63:0]   = '0;
          rwd_tx.byte_enable[127:64] = be_payload[i];
        end
        
        rwd_tx.tag[15:0]  = tag_extracted[i];
        rwd_tx.tag[31:16] = '0;
        rwd_tx.tag[32]    = 1'b0; 

        // Write directly to the HPA (rwd_addr_bytes already contains the 64B offset at bit 0!)
        shadow_mem[rwd_addr_bytes[i]] = data_payload[i];        
        egress_write_q.push_back(rwd_tx);

        `uvm_info(get_type_name(), $sformatf("[QUEUE_PUSH] Pushed to Egress Write Q. Current Queue Depth: %0d\n   Struct EGRS_IN {\n     opcode : 0x%0h\n     la     : 0x%0h\n     dpa    : 0x%0h\n     tag    : 0x%0h\n     poison : %0b\n     be     : 0x%0x\n     data   : 0x%0x\n   }", egress_write_q.size(), rwd_tx.opcode, calculated_la, rwd_tx.dpa, rwd_tx.tag, rwd_tx.poison, rwd_tx.byte_enable, rwd_tx.data), UVM_HIGH)
      end
    end
    else begin
      // Route HDM decode failure
      // TODO: error_completion_queue.push_back(error_tx);
    end
    processed[i] = 1'b1;
  end
endfunction:check_rwd_680b_boundaries

function bit kb_fwd_eng_scoreboard::predict_hpa_base_resolve(
  input bit [45:0] incoming_hpa,
  input string     txn_type // Added argument to distinguish REQ vs RWD
); 
  bit [9:0] region_match_vector = '0;
  int       match_count         = 0;
  int       matched_index       = -1;
  bit [23:0] hpa_chunk          = incoming_hpa[45:22]; 

  for (int n = 0; n < 10; n++) begin
    if (hdm_committed[n]) begin
      if ((hpa_chunk >= hdm_hpa_base[n][51:28]) && (hpa_chunk < hdm_hpa_top[n][51:28])) begin
        region_match_vector[n] = 1'b1;
        match_count++;
        matched_index = n;
      end
    end
  end

  if (match_count == 1) begin
    // Dynamically prepends "REQ_" or "RWD_" to the ID
    `uvm_info({txn_type, "_HDM_HPA_MATCH"}, $sformatf("HPA 0x%h hpa_chunk=0x%h clean match discovered on Decoder index %0d", incoming_hpa, hpa_chunk, matched_index), UVM_HIGH)
    calculated_la = predict_la_resolve(incoming_hpa, matched_index);
    return 1;
  end
  else if (match_count == 0) begin
    string msg = $sformatf("Injected HPA 0x%0h falls outside all active decoder targets.", incoming_hpa);
    `uvm_warning({txn_type, "_HDM_HPA_MISMATCH"}, msg)
    return 0;
  end
  else begin
    string msg = $sformatf("Overlapping address ranges hit! Vector bin allocation=%b", region_match_vector);
    `uvm_error({txn_type, "_HDM_HPA_MULTI_MATCH"}, msg)
    return 0;
  end
endfunction : predict_hpa_base_resolve


function bit [43:0] kb_fwd_eng_scoreboard::predict_la_resolve(input bit [45:0] hpa, int matching_idx);
  bit [63:0] la_offset;
  bit [45:0] combined_la;

  la_offset   = {18'd0,hpa} - (hdm_hpa_base[matching_idx]>>6); //51:6 hpa is subtracted from 51:6 of hdm_hpa_base[matching_idx] 
  combined_la = (hdm_dpa_base[matching_idx][51:6]) + la_offset;
  `uvm_info("dpa_offset",$sformatf(" la_offset=%0h la=%0h",la_offset,combined_la),UVM_HIGH) //UVM_DEBUG
  return combined_la[45:0];
endfunction : predict_la_resolve


// ---------------------------------------------------------------------------
//  Converts Egress Queue structures component-by-component to AXI
// ---------------------------------------------------------------------------
function void kb_fwd_eng_scoreboard::convert_egress_to_axi();
  EGRS_IN read_entry;
  EGRS_IN write_entry;
  
  // Local structural components typed directly from com_axi_pkg definitions
  axi_ar_src_t    tmp_ar;
  axi_aw_src_t    tmp_aw;
  axi_w1024_src_t tmp_w;

  // -------------------------------------------------------------------------
  //  Process Egress Read Transactions -> Map to AR Queue
  // -------------------------------------------------------------------------
  while (egress_read_q.size() > 0 && internal_rd_tokens >= TRANSMIT_TOKEN) begin
    r_track_t r_track_item;

    // Deduct the toll
    internal_rd_tokens -= TRANSMIT_TOKEN;
    `uvm_info("RD_TOKENS_USED",$sformatf("internal_rd_tokens=%0h",internal_rd_tokens),UVM_HIGH) // TODO:UVM_DEBUG

    read_entry = egress_read_q.pop_front();
    tmp_ar     = '{default: '0};
    
    // Push both tag and DPA context for the Ingress path
    r_track_item.tag = read_entry.tag;
    r_track_item.hpa = read_entry.hpa;
    tag_table_read_q.push_back(r_track_item);

    tmp_ar.valid = 1'b1;
    tmp_ar.id    = 0; // TODO:AWID/ARID = id[1:0] from DCD SRAM entry 
    tmp_ar.addr  = {15'h0, read_entry.dpa}; 
    tmp_ar.len   = 8'h00; // 1 beat on a 1024-bit wide bus represents 128B
    tmp_ar.burst = BURST;
    tmp_ar.qos   = 0;
    //tmp_ar.user   = ; // TODO:aruser[0] = 1 when error_response_type != 00 (write error)

    if (read_entry.tag[32] == 1'b1) begin
      tmp_ar.size  = 8'b0000_0111; // 128-Byte transfer width metric
    end 
    else begin
      tmp_ar.size  = 8'b0000_0110; // 64-Byte transfer width metric
    end

    ar_queue.push_back(tmp_ar);

    `uvm_info(get_type_name(), $sformatf("[FLIT_ED_AR] Converted EGRS_RD to AXI_AR. Addr: 0x%0h, ID: 0x%0h, Size: 0x%0h. AR Depth: %0d", 
              tmp_ar.addr, tmp_ar.id, tmp_ar.size, ar_queue.size()), UVM_HIGH)
  end

  // -------------------------------------------------------------------------
  // Process Egress Write Transactions -> Map to AW & W Queues (1024-bit Wide)
  // -------------------------------------------------------------------------
  while (egress_write_q.size() > 0 && internal_wr_tokens >= TRANSMIT_TOKEN) begin
   internal_wr_tokens -= TRANSMIT_TOKEN;   // Deduct the toll 
    write_entry = egress_write_q.pop_front();
    tmp_aw      = '{default: '0}; tmp_w       = '{default: '0};
    `uvm_info("WR_TOKENS_USED",$sformatf("internal_wr_tokens=%0h after popping current depth of egress_write_q=%0d",internal_wr_tokens,egress_write_q.size),UVM_HIGH)  // TODO:UVM_DEBUG

    // Push the full tag footprint (with bit[32] merge flag) to the Write Tag Table
    tag_table_write_q.push_back(write_entry.tag);

    // Setup Address Write Attributes (axi_aw_src_t)
    tmp_aw.valid   = 1'b1;
    tmp_aw.id      = '0; // TODO:AXI ID from DCD SRAM entry (id[1:0])
    tmp_aw.addr    = {15'h0, write_entry.dpa};
    tmp_aw.len     = 8'h00; 
    tmp_aw.burst   = BURST;   // Assigned 'INCR' burst code
    tmp_aw.qos     = 4'h0;
    tmp_aw.user    = '0;    // TODO:awuser[0] = 1 when error_response_type != 00 (write error)


    // Setup Common Write Data Attributes (axi_w1024_src_t)
    tmp_w.valid    = 1'b1;
    tmp_w.last     = 1'b1; 
    tmp_w.user     = '0;
    // as this is AXI4 do we need wid (doubtful as wid is mentioned in the spec)


    // -----------------------------------------------------------------------
    // AXI Size Attribute Assignment
    // -----------------------------------------------------------------------
    if (write_entry.tag[32] == 1'b1) begin
      tmp_aw.size = 8'b0000_0111; // 128B size burst attribute
      `uvm_info(get_type_name(), "[FLIT_ED_STEER] Tag[32]=1. Assigned 128B AXI Size.", UVM_HIGH)
    end 
    else begin
      tmp_aw.size = 8'b0000_0110; // 64B size burst attribute
      `uvm_info(get_type_name(), "[FLIT_ED_STEER] Tag[32]=0. Assigned 64B AXI Size.", UVM_HIGH)
    end

    // -----------------------------------------------------------------------
    // Direct Data & Strobe Mapping
    // -----------------------------------------------------------------------
    // Because check_rwd_680b_boundaries already steered the 64B chunks to the 
    // correct upper/lower lane, we can map the entire 1024-bit bus directly!
    tmp_w.data = write_entry.data;
    tmp_w.strb = write_entry.byte_enable;

    // Push completed single-beat AXI footprints to tracking reservoirs
    aw_queue.push_back(tmp_aw);
    w_queue.push_back(tmp_w);

    `uvm_info(get_type_name(), $sformatf("[FLIT_ED_WR] Converted EGRS_WR to AXI_AW/W Single-Beat. AW Depth: %0d, W Depth: %0d", 
              aw_queue.size(), w_queue.size()), UVM_HIGH)
  end

endfunction : convert_egress_to_axi


task kb_fwd_eng_scoreboard::compare_egress_axi_traffic();
  fork
    // =======================================================================
    // THREAD 1: Address Channel Checker (AW / AR)
    // =======================================================================
    forever begin
      kb_axi4_vendor_txn_t mon_addr_packet; // Local container to hold the generic packet pulled from the monitor FIFO
      axi_aw_src_t         act_aw, exp_aw;
      axi_ar_src_t         act_ar, exp_ar;

      // Execution sleeps here safely until the axi monitor pushes a transaction.
      address_fifo.get(mon_addr_packet); 
      //mon_addr_packet.print();
      // --- Case A: WRITE Address Phase (AW) ---

      // =======================================================================
      // DUT BUG TRAP: Spurious / Illegal Write Transaction
      // If aw_queue is empty but the monitor captures an AW transaction, it 
      // means the DUT processed an illegal packet that our reference model correctly 
      // dropped, or it generated a completely spurious write. We log the UVM_ERROR 
      // and intentionally flush this bad packet from address_fifo to prevent deadlocks.
      // =======================================================================

      if (mon_addr_packet.Direction == DENALI_CDN_AXI_DIRECTION_WRITE) begin
        if (aw_queue.size() == 0) begin
          `uvm_error("EG_AW_NO_REF_PACKET", $sformatf(" Monitor captured an AW transaction, but reference aw_queue is empty!\n  Context Details:\n  -> aw_queue size    : %0d (Expected entries built by reference model)\n  -> addr_fifo backing: %0d (Unprocessed monitor entries in FIFO queue)", aw_queue.size(), address_fifo.used()))//this .used might give wrong indication as data in it can be write/read address(need to revisit)
        end
        else begin
          exp_aw = aw_queue.pop_front();
          act_aw = convert_denali_to_aw(mon_addr_packet); // Convert

          // Direct struct comparison
          if (act_aw !== exp_aw) begin
            `uvm_error("EG_AW_MISMATCH", $sformatf(" AW Struct Mismatch!\n  Act: %p\n  Exp: %p", act_aw, exp_aw))
          end
          else begin
            `uvm_info("EG_AW_MATCH",$sformatf(" AW Struct Match!\n  Act: %p\n  Exp: %p", act_aw, exp_aw),UVM_LOW)
          end
        end
      end

      // --- Case B: READ Address Phase (AR) ---
      
      // =======================================================================
      // DUT BUG TRAP: Spurious / Illegal Read Transaction
      // If ar_queue is empty but the monitor captures an AR transaction, it 
      // means the DUT processed an illegal packet that our reference model correctly 
      // dropped, or it generated a completely spurious read. We log the UVM_ERROR 
      // and intentionally flush this bad packet from address_fifo to prevent deadlocks.
      // =======================================================================
      
      else if (mon_addr_packet.Direction == DENALI_CDN_AXI_DIRECTION_READ) begin
        if (ar_queue.size() == 0) begin
          `uvm_error("EG_AR_NO_REF_PACKET", $sformatf(" Monitor captured an AR transaction, but reference ar_queue is empty!\n  Context Details:\n  -> ar_queue size    : %0d (Expected entries built by reference model)\n  -> addr_fifo backing: %0d (Unprocessed monitor entries in FIFO queue)", ar_queue.size(), address_fifo.used()))
        end
        else begin
          exp_ar = ar_queue.pop_front();
          act_ar = convert_denali_to_ar(mon_addr_packet); // Convert

          if (act_ar !== exp_ar) begin
            `uvm_error("EG_AR_MISMATCH", $sformatf(" AR Struct Mismatch!\n  Act: %p\n  Exp: %p", act_ar, exp_ar))
          end
          else begin
            `uvm_info("EG_AR_MATCH",$sformatf(" AR Struct Match!\n  Act: %p\n  Exp: %p", act_ar, exp_ar),UVM_LOW)
          end
        end
      end
    end

    // =======================================================================
    // THREAD 2: Write Data Channel Checker (W)
    // =======================================================================
    forever begin
      kb_axi4_vendor_txn_t mon_w_packet; // Local container to hold the generic packet pulled from the monitor FIFO 
      axi_w1024_src_t      act_w, exp_w;

      w_fifo.get(mon_w_packet); 

      if (mon_w_packet.Direction == DENALI_CDN_AXI_DIRECTION_WRITE) begin
        if (w_queue.size() == 0) begin
          `uvm_error(get_type_name(), $sformatf("[EG_W_MISMATCH] Monitor captured W payload data, but reference w_queue is empty!\n  Context Details:\n  -> w_queue size  : %0d (Expected entries built by reference model)\n  -> w_fifo backing: %0d (Unprocessed monitor entries in FIFO queue)", w_queue.size(), w_fifo.used()))          
        end
        else begin
          exp_w = w_queue.pop_front();
          act_w = convert_denali_to_w(mon_w_packet); // Convert

          if (act_w !== exp_w) begin
            `uvm_error("EG_W_MISMATCH", $sformatf(" Write Payload Struct Mismatch!\n  Act: %p\n  Exp: %p", act_w, exp_w))
          end
          else begin
            `uvm_info("EG_W_MATCH",$sformatf(" Write Payload Struct Match!\n  Act: %p\n  Exp: %p", act_w, exp_w),UVM_LOW)
          end
        end
      end
    end
    

    // =======================================================================
    // THREAD 3: Event-Driven Response Channel Checker (B / R)
    // =======================================================================
    forever begin
      kb_axi4_vendor_txn_t mon_resp_packet; 
      resp_fifo.get(mon_resp_packet);

      // --- Case A: AXI Downstream Slave Read Completion (R Channel) ---
      if (mon_resp_packet.Direction == DENALI_CDN_AXI_DIRECTION_READ) begin
        axi_r1024_src_t act_r;
        r_track_t       meta;
        
        act_r = convert_denali_to_r(mon_resp_packet);

        if (tag_table_read_q.size() == 0) begin
          `uvm_error(get_type_name(), "[ING_AXI_ORPHAN] AXI Slave returned Read Data, but tag_table_read_q is empty!")
          continue;
        end

        // Pop the context 
        meta = tag_table_read_q.pop_front();

        // -------------------------------------------------------------------
        // The Splitter
        // -------------------------------------------------------------------
        if (meta.tag[32] == 1'b1) begin
          // It is a merged 128B transaction -> Split into TWO 64B pushes
          exp_cxl_drc_t pkt_lsb, pkt_msb;

          // Push 1: LSB Part
          pkt_lsb.s2m_tag  = meta.tag[15:0];
          pkt_lsb.s2m_data = act_r.data[511:0];
          pkt_lsb.s2m_poison = (act_r.resp == 2'b10); // SLVERR mapping to poison
          exp_drc_q.push_back(pkt_lsb);

          // Push 2: MSB Part
          pkt_msb.s2m_tag  = meta.tag[31:16];
          pkt_msb.s2m_data = act_r.data[1023:512];
          pkt_msb.s2m_poison = (act_r.resp == 2'b10); 
          exp_drc_q.push_back(pkt_msb);

          `uvm_info(get_type_name(), $sformatf("[AXI_R_SPLIT] Split 1024-bit AXI RDATA into two 64B expected DRCs. Tags: 0x%04h & 0x%04h", pkt_lsb.s2m_tag, pkt_msb.s2m_tag), UVM_HIGH)

          // Look up using HPA (Lower) and HPA+1 (Upper)
          //if (shadow_mem.exists(meta.hpa) && shadow_mem.exists(meta.hpa + 1)) begin
          if (shadow_mem.exists(meta.hpa)) begin
            if (shadow_mem[meta.hpa] !== act_r.data[511:0])
              `uvm_error("E2E_DATA_MISMATCH", $sformatf("[128B_LOWER] HPA: 0x%0h\nExp: 0x%0x\nAct: 0x%0x", meta.hpa, shadow_mem[meta.hpa], act_r.data[511:0]))
          end
          
          if (shadow_mem.exists(meta.hpa + 1)) begin
            if (shadow_mem[meta.hpa + 1] !== act_r.data[1023:512])
              `uvm_error("E2E_DATA_MISMATCH", $sformatf("[128B_UPPER] HPA: 0x%0h\nExp: 0x%0x\nAct: 0x%0x", meta.hpa + 1, shadow_mem[meta.hpa + 1], act_r.data[1023:512]))
          end          
        end
        else begin
          // It is a standalone 64B transaction -> Single push
          exp_cxl_drc_t pkt_single;
          pkt_single.s2m_tag = meta.tag[15:0];
          pkt_single.s2m_poison = (act_r.resp == 2'b10);
          
          // Use DPA bit 0 to know which half of the AXI bus the data is sitting on
          if (meta.hpa[0] == 1'b0) begin
            pkt_single.s2m_data = act_r.data[511:0];
          end 
          else begin
            pkt_single.s2m_data = act_r.data[1023:512];
          end
          
          exp_drc_q.push_back(pkt_single);
          `uvm_info(get_type_name(), $sformatf("[AXI_R_SINGLE] Mapped 1024-bit AXI RDATA into single 64B expected DRC. Tag: 0x%04h", pkt_single.s2m_tag), UVM_HIGH)

          // Look up using exactly the HPA that was saved
          if (shadow_mem.exists(meta.hpa)) begin
            if (shadow_mem[meta.hpa] !== pkt_single.s2m_data)
              `uvm_error("E2E_DATA_MISMATCH", $sformatf("[64B_SINGLE] HPA: 0x%0h\nExp: 0x%0x\nAct: 0x%0x", meta.hpa, shadow_mem[meta.hpa], pkt_single.s2m_data))                  
            else 
            `uvm_info("E2E_DATA_MATCH", $sformatf("[64B_SINGLE] HPA: 0x%0h\nExp: 0x%0x\nAct: 0x%0x", meta.hpa, shadow_mem[meta.hpa], pkt_single.s2m_data),UVM_LOW)
          end
        end
      end

      // --- Case B: AXI Downstream Slave Write Ack (B Channel) ---
      else if (mon_resp_packet.Direction == DENALI_CDN_AXI_DIRECTION_WRITE) begin
        axi_b_src_t act_b;
        bit [32:0]  meta_tag;
        
        act_b = convert_denali_to_b(mon_resp_packet);

        if (tag_table_write_q.size() == 0) begin
          `uvm_error(get_type_name(), "[ING_AXI_ORPHAN] AXI Slave returned Write Ack (B), but tag_table_write_q is empty!")
          continue;
        end

        // Pop the write context 
        meta_tag = tag_table_write_q.pop_front();

        // -------------------------------------------------------------------
        // NDR Splitter Logic
        // -------------------------------------------------------------------
        if (meta_tag[32] == 1'b1) begin
          // Merged 128B Write -> Split into TWO expected NDR completions
          exp_cxl_ndr_t pkt_lsb, pkt_msb;

          // Push 1: LSB Tag
          pkt_lsb.s2m_tag    = meta_tag[15:0];
          pkt_lsb.s2m_status = act_b.resp; 
          exp_ndr_q.push_back(pkt_lsb);

          // Push 2: MSB Tag
          pkt_msb.s2m_tag    = meta_tag[31:16];
          pkt_msb.s2m_status = act_b.resp; 
          exp_ndr_q.push_back(pkt_msb);

          `uvm_info(get_type_name(), $sformatf("[AXI_B_SPLIT] Split 128B AXI B-Resp into two expected CXL NDRs. Tags: 0x%04h & 0x%04h", pkt_lsb.s2m_tag, pkt_msb.s2m_tag), UVM_HIGH)
        end
        else begin
          // Standalone 64B Write -> Single NDR completion
          exp_cxl_ndr_t pkt_single;
          
          pkt_single.s2m_tag    = meta_tag[15:0];
          pkt_single.s2m_status = act_b.resp;
          
          exp_ndr_q.push_back(pkt_single);
          `uvm_info(get_type_name(), $sformatf("[AXI_B_SINGLE] Mapped 64B AXI B-Resp into single expected CXL NDR. Tag: 0x%04h", pkt_single.s2m_tag), UVM_HIGH)
        end
      end      
    end

  join
endtask : compare_egress_axi_traffic


// ---------------------------------------------------------------------------
// Denali VIP to Local Struct Conversion Functions
// ---------------------------------------------------------------------------
function axi_aw_src_t kb_fwd_eng_scoreboard::convert_denali_to_aw(kb_axi4_vendor_txn_t txn);
  axi_aw_src_t aw;
  
  aw.valid = 1'b1;
  aw.addr  = txn.StartAddress;
  aw.len   = txn.Alen;
  aw.size  = txn.Size-1;
  aw.id    = txn.IdTag;
  aw.burst = txn.Kind; 
  aw.qos   = '0;      // Assuming QoS is 0 as default
  aw.user  = {<<{txn.Auser}};
  
  return aw;
endfunction : convert_denali_to_aw

function axi_ar_src_t kb_fwd_eng_scoreboard::convert_denali_to_ar(kb_axi4_vendor_txn_t txn);
  axi_ar_src_t ar;
  
  ar.valid = 1'b1;
  ar.addr  = txn.StartAddress;
  ar.len   = txn.Alen;
  ar.size  = txn.Size-1;
  ar.id    = txn.IdTag;
  ar.burst = txn.Kind;
  ar.qos   = '0; 
  ar.user  = {<<{txn.Auser}};
  
  return ar;
endfunction : convert_denali_to_ar

function axi_w1024_src_t kb_fwd_eng_scoreboard::convert_denali_to_w(kb_axi4_vendor_txn_t txn);
  axi_w1024_src_t w;
  
  w.valid = 1'b1;
  w.last  = txn.Last;
  w.user  = {<<{txn.User}};

  // Initialize to zero to prevent X-propagation
  w.data  = '0;
  w.strb  = '0;

  //w.data = {<<{txn.PhysicalData}};
  //w.strb ={<<{ txn.Strobe[127:0]}};
  w.strb ={txn.Strobe[127:0]};
  
  foreach (txn.PhysicalData[i]) begin
    w.data[(i * 32) +: 32] = txn.PhysicalData[i];
  end
  
  return w;
endfunction : convert_denali_to_w



// ---------------------------------------------------------------------------
// Denali VIP to Local/com_axi_pkg Struct Conversion (Ingress Responses)
// ---------------------------------------------------------------------------
function axi_b_src_t kb_fwd_eng_scoreboard::convert_denali_to_b(kb_axi4_vendor_txn_t txn);
  axi_b_src_t b;
  b.valid = 1'b1;
  b.id    = txn.IdTag;
  b.resp  = txn.Resp;
  b.user  = {<<{txn.Buser}};
  return b;
endfunction : convert_denali_to_b

function axi_r1024_src_t kb_fwd_eng_scoreboard::convert_denali_to_r(kb_axi4_vendor_txn_t txn);
  axi_r1024_src_t r;
  
  r.valid = 1'b1;
  r.id    = txn.IdTag;
  r.resp  = txn.Resp;
  r.last  = txn.Last;
  r.user  = {<<{txn.User}};
  
  r.data  = '0;
  
  // Little-Endian mapping matching AXI hardware lanes
  foreach (txn.PhysicalData[i]) begin
    r.data[(i * 32) +: 32] = txn.PhysicalData[i];
  end
  
  return r;
endfunction : convert_denali_to_r


// ---------------------------------------------------------------------------
// Ingress Checker: STRICT IN-ORDER S2M No Data Responses (NDR)
// ---------------------------------------------------------------------------
task kb_fwd_eng_scoreboard::process_s2m_ndr_traffic();
  forever begin
    kb_cxl_mon_item cxl_act_ndr;
    exp_cxl_ndr_t   exp_ndr;

    // Wait for actual CXL NDR completion from the DUT
    cxl_s2m_ndr_fifo.get(cxl_act_ndr);

    `uvm_info("NUM_NDR","new ndr found",UVM_HIGH)    

    // Check for phantom packets
    if (exp_ndr_q.size() == 0) begin
      `uvm_error(get_type_name(), $sformatf("[ING_NDR_ORPHAN] DUT emitted CXL NDR for tag 0x%04h, but expected queue is empty!\n  Context Details:\n  -> exp_ndr_q size        : %0d (Expected entries built by reference model)\n  -> cxl_s2m_ndr_fifo used : %0d (Unprocessed monitor entries in FIFO queue)", cxl_act_ndr.s2m_tag, exp_ndr_q.size(), cxl_s2m_ndr_fifo.used()))      
      continue;
    end

    // STRICT IN-ORDER POP
    exp_ndr = exp_ndr_q.pop_front();

    // Enforce Ordering (Tag Match)
    if (cxl_act_ndr.s2m_tag !== exp_ndr.s2m_tag) begin
      `uvm_error("ING_NDR_TAG_MISMATCH", $sformatf("Out-of-order response or tag mismatch!\n  Expected Tag: 0x%04h\n  Actual Tag  : 0x%04h", exp_ndr.s2m_tag, cxl_act_ndr.s2m_tag))
    end
    else begin
      `uvm_info("ING_NDR_TAG_MATCH",$sformatf("exp_tag=0x%0h act_tag=0x%0h",exp_ndr.s2m_tag,cxl_act_ndr.s2m_tag),UVM_LOW)
    end

    // Verify Status mapping
    if (exp_ndr.s2m_status != 2'b00) begin
      // if (cxl_act_ndr.s2m_drc_opcode != kb_cxl_pkg::NDR_ERR) begin 
      //   `uvm_error(get_type_name(), $sformatf("[ING_NDR_STATUS_ERR] AXI returned Slave Error for Tag 0x%04h, but CXL DUT issued a normal success NDR!", cxl_act_ndr.s2m_tag))
      // end
    end

    `uvm_info(get_type_name(), $sformatf("[ING_NDR_PASS] Verified strictly in-order 64B NDR Completion for Tag 0x%04h", cxl_act_ndr.s2m_tag), UVM_MEDIUM)
  end
endtask : process_s2m_ndr_traffic




// ---------------------------------------------------------------------------
// Ingress Checker: STRICT IN-ORDER S2M Data Response Completions (DRC)
// ---------------------------------------------------------------------------
task kb_fwd_eng_scoreboard::process_s2m_drc_traffic();
  forever begin
    kb_cxl_mon_item cxl_act_drc;
    exp_cxl_drc_t   exp_drc;

    // Wait for actual CXL completion from the DUT
    cxl_s2m_drc_fifo.get(cxl_act_drc);
    `uvm_info("NUM_DRS","new drs found",UVM_HIGH)    
    // Check for phantom/unexpected packets
    if (exp_drc_q.size() == 0) begin
      `uvm_error(get_type_name(), $sformatf("[ING_DRC_ORPHAN] DUT emitted CXL DRC for tag 0x%04h, but expected queue is empty!\n  Context Details:\n  -> exp_drc_q size        : %0d (Expected entries built by reference model)\n  -> cxl_s2m_drc_fifo used : %0d (Unprocessed monitor entries in FIFO queue)", cxl_act_drc.s2m_tag, exp_drc_q.size(), cxl_s2m_drc_fifo.used()))
      continue;
    end

    // STRICT IN-ORDER POP: Always take the oldest expected transaction
    exp_drc = exp_drc_q.pop_front();

    if (cxl_act_drc.s2m_tag !== exp_drc.s2m_tag) begin
      `uvm_error(get_type_name(), $sformatf("[ING_DRC_TAG_ERR] tag mismatch!\n  Expected Tag: 0x%04h\n  Actual Tag  : 0x%04h", exp_drc.s2m_tag, cxl_act_drc.s2m_tag))
    end
    else begin
      `uvm_info("DRS_TAG_PASS",$sformatf("exp_tag=0x%0h act_tag=0x%0h",exp_drc.s2m_tag,cxl_act_drc.s2m_tag),UVM_LOW)
    end
    // Opcode and Error Translation Check
    if (exp_drc.s2m_poison == 1'b0) begin
      // Normal Success Path: Opcode MUST be MemData (000b)
      if (cxl_act_drc.s2m_drc_opcode !== 3'b000) begin
         `uvm_error(get_type_name(), $sformatf("[ING_DRC_OPC_FAULT] Expected standard MemData (000b) for Tag 0x%04h, but DUT issued opcode 0x%0h!", cxl_act_drc.s2m_tag, cxl_act_drc.s2m_drc_opcode))
       end
    end 
    else begin
      // Error Path: If you mapped AXI DECERR (2'b11) to this transaction, 
      // you could assert that the DUT outputs MemData-NXM (001b) here
      // TODO: should we consider DECERR ???
      // Otherwise, check that Poison is correctly asserted for SLVERR.
      if (cxl_act_drc.s2m_poison !== 1'b1) begin
         `uvm_error(get_type_name(), $sformatf("[ING_DRC_POISON_FAULT] AXI reported an error for Tag 0x%04h, but CXL DUT did not assert the Poison flag!", cxl_act_drc.s2m_tag))
      end
    end

    // Verify Data Payload
    if (cxl_act_drc.s2m_data !== exp_drc.s2m_data) begin
      `uvm_error(get_type_name(), $sformatf("[ING_DRC_DATA_ERR] 64B Data Mismatch for Tag 0x%04h!\n  Act: 0x%0x\n  Exp: 0x%0x", cxl_act_drc.s2m_tag, cxl_act_drc.s2m_data, exp_drc.s2m_data))
    end 
  
    else begin
      `uvm_info(get_type_name(), $sformatf("[ING_DRC_PASS] Verified strictly in-order 64B DRC for Tag 0x%04h", cxl_act_drc.s2m_tag), UVM_MEDIUM)
    end
  end
endtask : process_s2m_drc_traffic


// ---------------------------------------------------------------------------
// APB Configuration Monitor Thread
// ---------------------------------------------------------------------------
task kb_fwd_eng_scoreboard::process_apb_traffic();
  forever begin
    denaliCdn_apbTransaction apb_pkt; 

    // Sleep here until the APB monitor pushes a packet
    apb_fifo.get(apb_pkt);
    if (apb_pkt.Direction == DENALI_CDN_APB_DIRECTION_WRITE) begin 
      `uvm_info("APB_SB", $sformatf("Received APB Write: Addr=0x%0h, Data=0x%0h", apb_pkt.Addr, apb_pkt.Data), UVM_HIGH)
      
      // Pass the extracted address and data to our mapping function
      get_apb_config_data(apb_pkt.Addr, apb_pkt.Data);
    end
  end
endtask : process_apb_traffic



//=============================================================================
// APB Store mode configuration (fe_top_mm mapping - Updated Offsets)
//=============================================================================
task kb_fwd_eng_scoreboard::get_apb_config_data(bit [63:0] addr, bit [31:0] data);
  // -------------------------------------------------------------------------
  // 1. DYNAMIC SRAM ADDRESS MAP LUT (Indices 0 to 131071)
  // Base Offset: 0x0, End Offset: 0x7FFFF (131072 entries * 4 bytes)
  // -------------------------------------------------------------------------

  bit [63:0] SRAM_BASE = 64'h0; 
  
  if (addr >= SRAM_BASE && addr <= (SRAM_BASE + 64'h7FFFF)) begin
    int lut_idx;

    // Divide by 8 to create a dense index (0 to 65535) for 64-bit aligned words
    lut_idx = (addr - SRAM_BASE) / 8;

    if (lut_idx < 65536) begin
      // Bit 2 determines if the 32-bit write targets the MSB or LSB RAM
      if (addr[2] == 1'b1) begin
        // MSB addresses end in 4 or C (e.g., 0x00004, 0x1FFFC)
        address_map_lut[lut_idx] = data;
        `uvm_info("APB_LUT_CFG_MSB", $sformatf("Configured MSB_LUT[%0d] at addr 0x%0h with data 0x%0h", lut_idx, addr, data), UVM_HIGH)
      end 
      else begin
        // LSB addresses end in 0 or 8 (e.g., 0x00000, 0x1FFF8)
        lsb_address_map_lut[lut_idx] = data;
        `uvm_info("APB_LUT_CFG_LSB", $sformatf("Configured LSB_LUT[%0d] at addr 0x%0h with data 0x%0h", lut_idx, addr, data), UVM_HIGH)
      end
    end
  end
  // -------------------------------------------------------------------------
  // 2. DYNAMIC DECODER ARRAY (Indices 0 to 9)
  // New Base: 0x80010, Stride: 0x20, End: 0x8014B
  // -------------------------------------------------------------------------
  else if (addr >= 64'h80010 && addr <= 64'h8014B) begin
    int       idx;
    bit [7:0] offset;

    // Extract using the new 0x80010 base
    idx    = (addr - 64'h80010) / 'h20;
    offset = (addr - 64'h80010) % 'h20;

    if (idx < 10) begin
      case (offset)
        8'h00: r_base_low[idx]  = data;
        8'h04: r_base_high[idx] = data;
        8'h08: r_size_low[idx]  = data;
        8'h0C: r_size_high[idx] = data;
        8'h14: r_skip_low[idx]  = data;
        8'h18: r_skip_high[idx] = data;
        default: `uvm_warning("APB_CFG", $sformatf("Write to unmapped offset 0x%0h in decoder %0d", offset, idx))
      endcase
      
      `uvm_info("APB_CFG", $sformatf("Configured Decoder[%0d] offset 0x%0h with data 0x%0h", idx, offset, data), UVM_HIGH)
      
      // Trigger recalculation of hardware boundaries
      update_hdm_calculations();
    end
  end
  
  // -------------------------------------------------------------------------
  // 3. GLOBAL REGISTERS (rd/wr burst and token logic)
  // New Base: 0x8014C
  // -------------------------------------------------------------------------
  else begin
    case (addr)
      64'h8014C: rd_max_burst_rate_inst = data;
      64'h80150: rd_cm_ratio_inst       = data;
      64'h80154: rd_current_token_inst  = data;
      64'h80158: rd_reset_token         = data;

      64'h8015C: wr_max_burst_rate_inst = data;
      64'h80160: wr_cm_ratio_inst       = data;
      64'h80164: wr_current_token_inst  = data;
      64'h80168: wr_reset_token         = data;

      default: ; // Safely ignore unrelated APB writes
    endcase
  end
endtask : get_apb_config_data


// ---------------------------------------------------------------------------
// Dynamic HDM Decoder Sync (Pulls state from local APB Arrays)
// ---------------------------------------------------------------------------
function void kb_fwd_eng_scoreboard::update_hdm_calculations();
  
  // Running accumulator to track where the previous decoder's DPA range ended
  bit [63:0] prev_dpa_end = 64'h0; 
  
  for (int i = 0; i < 10; i++) begin
    bit [63:0] full_base, full_size, full_top, full_skip, calc_dpa_base;

    // Extract and concatenate the 64-bit values directly from our local APB-populated arrays
    full_base = {r_base_high[i], r_base_low[i]};
    full_size = {r_size_high[i], r_size_low[i]};
    full_skip = {r_skip_high[i], r_skip_low[i]};

    // Slice HPA bits [51:28] exactly as required for the hpa_chunk comparison
    full_top        = full_base + full_size;
    hdm_hpa_base[i] = full_base;
    hdm_hpa_top[i]  = full_top;

    // -----------------------------------------------------------------------
    // The CXL DPA Base Calculation
    // -----------------------------------------------------------------------
    if (i == 0) begin
      // Decoder[0].DPABase = Decoder[0].DPASkip;
      calc_dpa_base = full_skip;
    end 
    else begin
      // Decoder[m].DPABase = Decoder[m-1].DPABase + Decoder[m-1].Size + Decoder[m].DPASkip
      // (prev_dpa_end already contains Decoder[m-1].DPABase + Decoder[m-1].Size)
      calc_dpa_base = prev_dpa_end + full_skip;
    end

    // Store it in your scoreboard's array (Assuming hdm_dpa_base is sized to fit this)
    hdm_dpa_base[i] = calc_dpa_base;
    $display("64 bit value is %h hdm_dpa_base[%0d]=%h",hdm_dpa_base[i],i,hdm_dpa_base[i]);
    // Update the running accumulator for the NEXT loop iteration
    prev_dpa_end = calc_dpa_base + full_size;

    // Only print if the decoder is actually populated to save log space
    //if (full_size > 0) begin
      //`uvm_info(get_type_name(), $sformatf("Synced Dec %0d | FULL HPA: 0x%0h to 0x%0h | HPA [51:28]: 0x%0h to 0x%0h | DPA Base: 0x%0h",  i, hdm_hpa_base[i], hdm_hpa_top[i],hdm_hpa_base[i][51:28], hdm_hpa_top[i][51:28], hdm_dpa_base[i]), UVM_HIGH)
    //end
  end
endfunction : update_hdm_calculations


`ifdef KB_USE_BACKDOOR_CFG
// ---------------------------------------------------------------------------
// Zero-Time Memory Extraction
// ---------------------------------------------------------------------------
task kb_fwd_eng_scoreboard::sync_lut_from_ral();
  int            msb_data_out, lsb_data_out;
  string         msb_base_path;
  string         lsb_base_path;
  string         msb_mem_path;
  string         lsb_mem_path;
  uvm_reg_data_t msb_data, lsb_data;
  int            inst_idx;
  int            local_idx;

  `uvm_info(get_type_name(), "Synchronizing 64k LUT across MSB and LSB physical SRAM banks via uvm_hdl_read...", UVM_LOW)

  // Static parts of the paths up to the wrapper
  msb_base_path = "kb_fwd_eng_tb_top.dut_wrapper_i.u_cp7_fe.u_dcd_top_inst.u_dcd_sram_wrapper_aw_msb_wrapper_inst";
  lsb_base_path = "kb_fwd_eng_tb_top.dut_wrapper_i.u_cp7_fe.u_dcd_top_inst.u_dcd_sram_wrapper_aw_lsb_wrapper_inst";

  // Loop through all 65,536 logical indices
  for (int i = 0; i < 65536; i++) begin
    
    // Calculate physical instance (0-3) and local row (0-16383)
    inst_idx  = i / 16384; 
    local_idx = i % 16384;

    // Construct the direct paths 
    msb_mem_path = $sformatf("%s.u_com_ram_1rw_inst%0d.g_tech4.g_16384x36.g_vt1.u_ram_1rw.u_ram_core.memory[%0d]", 
                             msb_base_path, inst_idx, local_idx);
                             
    lsb_mem_path = $sformatf("%s.u_com_ram_1rw_inst%0d.g_tech4.g_16384x39.g_vt1.u_ram_1rw.u_ram_core.memory[%0d]", 
                             lsb_base_path, inst_idx, local_idx);
    
    // --- 1. Extract MSB ---
    if (!uvm_hdl_read(msb_mem_path, msb_data_out)) begin
      `uvm_error(get_type_name(), $sformatf("Failed MSB backdoor read at calculated path: %s", msb_mem_path))
      break; 
    end 
    else begin
      msb_data = msb_data_out;
      address_map_lut[i] = msb_data[31:0];      
    end
    
    // --- 2. Extract LSB ---
    if (!uvm_hdl_read(lsb_mem_path, lsb_data_out)) begin
      `uvm_error(get_type_name(), $sformatf("Failed LSB backdoor read at calculated path: %s", lsb_mem_path))
      break; 
    end 
    else begin
      lsb_data = lsb_data_out;
      lsb_address_map_lut[i] = lsb_data[31:0]; // Extracts the 32-bit APB payload 
    end
    
    `uvm_info("BACKDOOR_LUT", $sformatf("LUT[%0d] MSB[28:0]=%0h MSB[26:0]=%0h LSB=%0h", i, msb_data[28:0], msb_data[26:0], lsb_data[31:0]), UVM_HIGH)      
  end
  
  `uvm_info(get_type_name(), "SRAM backdoor synchronization complete.", UVM_LOW)
endtask : sync_lut_from_ral


// ---------------------------------------------------------------------------
// Backdoor Configuration Sync (Pulls from RAL Mirrored Values)
// ---------------------------------------------------------------------------
function void kb_fwd_eng_scoreboard::sync_cfg_from_ral_backdoor();
  
  if (h_env_cfg.h_regblock == null) begin
    `uvm_fatal(get_type_name(), "Cannot backdoor sync: h_regblock is null!")
    return;
  end

  `uvm_info(get_type_name(), "Performing Zero-Time Backdoor Configuration Sync from RAL...", UVM_LOW)

  //  Sync the 10 Dynamic Decoders
  for (int i = 0; i < 10; i++) begin
    uvm_reg r_base_l, r_base_h, r_size_l, r_size_h, r_skip_l, r_skip_h;

    // Grab the register handles dynamically
    r_base_l = h_env_cfg.h_regblock.get_reg_by_name($sformatf("base_low_inst_%0d", i));
    r_base_h = h_env_cfg.h_regblock.get_reg_by_name($sformatf("base_high_inst_%0d", i));
    r_size_l = h_env_cfg.h_regblock.get_reg_by_name($sformatf("size_low_inst_%0d", i));
    r_size_h = h_env_cfg.h_regblock.get_reg_by_name($sformatf("size_high_inst_%0d", i));
    r_skip_l = h_env_cfg.h_regblock.get_reg_by_name($sformatf("skip_low_inst_%0d", i));
    r_skip_h = h_env_cfg.h_regblock.get_reg_by_name($sformatf("skip_high_inst_%0d", i));

    if (r_base_l != null) r_base_low[i]  = r_base_l.get_mirrored_value();
    if (r_base_h != null) r_base_high[i] = r_base_h.get_mirrored_value();
    if (r_size_l != null) r_size_low[i]  = r_size_l.get_mirrored_value();
    if (r_size_h != null) r_size_high[i] = r_size_h.get_mirrored_value();
    if (r_skip_l != null) r_skip_low[i]  = r_skip_l.get_mirrored_value();
    if (r_skip_h != null) r_skip_high[i] = r_skip_h.get_mirrored_value();
  end

  //  Execute the exact same math calculation used by the APB thread!
  update_hdm_calculations();

    `uvm_info("DECODER_VALUES",$sformatf("\n  hdm_hpa_base=%0p\n  hdm_hpa_top=%0p\n  hdm_dpa_base=%0p",hdm_hpa_base,hdm_hpa_top,hdm_dpa_base),UVM_HIGH)
  foreach(hdm_dpa_base[i])begin
    `uvm_info("DECODER_VALUES",$sformatf("\n  hdm_dpa_base[%0d]=%h",i,hdm_dpa_base[i]),UVM_HIGH)
  end

  `uvm_info(get_type_name(), "Backdoor sync complete.", UVM_LOW)
endfunction : sync_cfg_from_ral_backdoor
`endif //KB_USE_BACKDOOR_CFG

`ifdef KB_USE_BACKDOOR_CFG
// ---------------------------------------------------------------------------
// Lightweight Per-Cycle Config Sync (No Prints)
// ---------------------------------------------------------------------------
function void kb_fwd_eng_scoreboard::sync_rates_from_ral_backdoor();
  uvm_reg tmp_reg;
  
  if (h_env_cfg.h_regblock == null) return;

  // --- RD Registers ---
  tmp_reg = h_env_cfg.h_regblock.get_reg_by_name("rd_max_burst_rate_inst");
  if (tmp_reg != null) rd_max_burst_rate_inst = tmp_reg.get_mirrored_value();

  tmp_reg = h_env_cfg.h_regblock.get_reg_by_name("rd_cm_ratio_inst");
  if (tmp_reg != null) rd_cm_ratio_inst = tmp_reg.get_mirrored_value();

  tmp_reg = h_env_cfg.h_regblock.get_reg_by_name("rd_current_token_inst");
  if (tmp_reg != null) rd_current_token_inst = tmp_reg.get_mirrored_value();

  tmp_reg = h_env_cfg.h_regblock.get_reg_by_name("rd_reset_token");
  if (tmp_reg != null) rd_reset_token = tmp_reg.get_mirrored_value();

  // --- WR Registers ---
  tmp_reg = h_env_cfg.h_regblock.get_reg_by_name("wr_max_burst_rate_inst");
  if (tmp_reg != null) wr_max_burst_rate_inst = tmp_reg.get_mirrored_value();

  tmp_reg = h_env_cfg.h_regblock.get_reg_by_name("wr_cm_ratio_inst");
  if (tmp_reg != null) wr_cm_ratio_inst = tmp_reg.get_mirrored_value();

  tmp_reg = h_env_cfg.h_regblock.get_reg_by_name("wr_current_token_inst");
  if (tmp_reg != null) wr_current_token_inst = tmp_reg.get_mirrored_value();

  tmp_reg = h_env_cfg.h_regblock.get_reg_by_name("wr_reset_token");
  if (tmp_reg != null) wr_reset_token = tmp_reg.get_mirrored_value();

  // Note: You can also include the 10 Decoder bounds (r_base_low, etc.) here 
  // if those are also dynamically backdoored mid-simulation!
endfunction : sync_rates_from_ral_backdoor

`endif //KB_USE_BACKDOOR_CFG


// ---------------------------------------------------------------------------
// Rate Limiter Calculation (Per-Cycle Token Refill Only)
// ---------------------------------------------------------------------------
function void kb_fwd_eng_scoreboard::calculate_rate_limits(kb_cxl_bus_snap snap);



  // Reset / Link Down Condition
  if (snap.rst_n == 1'b0) begin
    internal_rd_tokens = rd_reset_token;
    internal_wr_tokens = wr_reset_token;
    return; // Exit the function, no tokens accumulate during reset
  end

  // -------------------------------------------------------------------------
  // READ FLOW TOKEN ACCUMULATION
  // -------------------------------------------------------------------------
  begin 
    bit [31:0] rd_rate       = rd_max_burst_rate_inst[15:0];
    bit [31:0] rd_max_burst  = rd_max_burst_rate_inst[31:16];
    bit [4:0]  rd_cm_ratio   = rd_cm_ratio_inst[4:0];
    
    bit [31:0] rd_final_rate = rd_rate >> rd_cm_ratio;
    bit [31:0] rd_cap        = rd_max_burst; //rd_max_burst << 16;

    if ((internal_rd_tokens + rd_final_rate) > rd_cap) begin
      internal_rd_tokens = rd_cap;
    end 
    else begin
      internal_rd_tokens += rd_final_rate;
    end

    // --- Diagnostic Print ---
    `uvm_info("TOKEN_DBG_RD", $sformatf(
      "Cfg[Rate:%0h Burst:%0h CM:%0d] -> Calc[FinalRate:%0h Cap:%0h] | Current Tokens: 0x%0h", 
      rd_rate, rd_max_burst, rd_cm_ratio, rd_final_rate, rd_cap, internal_rd_tokens), UVM_DEBUG)   // TODO:UVM_DEBUG 
  end

  // -------------------------------------------------------------------------
  // WRITE FLOW TOKEN ACCUMULATION
  // -------------------------------------------------------------------------
  begin
    bit [31:0] wr_rate       = wr_max_burst_rate_inst[15:0];
    bit [31:0] wr_max_burst  = wr_max_burst_rate_inst[31:16];
    bit [4:0]  wr_cm_ratio   = wr_cm_ratio_inst[4:0];
    
    bit [31:0] wr_final_rate = wr_rate >> wr_cm_ratio;
    bit [31:0] wr_cap        = wr_max_burst; //wr_max_burst << 16;

    if ((internal_wr_tokens + wr_final_rate) > wr_cap) begin
      internal_wr_tokens = wr_cap;
    end 
    else begin
      internal_wr_tokens += wr_final_rate;
    end
    // --- Diagnostic Print ---
    `uvm_info("TOKEN_DBG_WR", $sformatf(
      "Cfg[Rate:%0h Burst:%0h CM:%0d] -> Calc[FinalRate:%0h Cap:%0h] | Current Tokens: 0x%0h", 
      wr_rate, wr_max_burst, wr_cm_ratio, wr_final_rate, wr_cap, internal_wr_tokens), UVM_DEBUG)   // TODO:UVM_DEBUG 
  end

endfunction : calculate_rate_limits


`endif // KB_FWD_ENG_SCOREBOARD_SV