// *************************************************************************
//
// graph_aggregator: extract IPv4 5-tuples from ingress packets and pack
// them into host-bound frames (Anonymized Network Sensing Graph Challenge,
// steps 1-2: stream packets, extract source/destination info).
//
// Ingress (s_axis_*): packets from the CMAC RX path (via packet adapter),
// 512-bit AXI-Stream @ 250 MHz. Never back-pressured: tready is tied high
// so the module always keeps up with line rate. Original packets are
// consumed (dropped) after extraction; only the records go to the host.
//
// Egress (m_axis_*): aggregated frames to the QDMA C2H path. Frame format
// (all multi-byte fields big-endian / network order):
//   slot 0 (bytes 0..15) -- link header:
//     bytes 0..5    ETH_DST_MAC
//     bytes 6..11   ETH_SRC_MAC
//     bytes 12..13  ETH_TYPE (custom, for host-side filtering)
//     bytes 14..15  record count K
//   slot 1 (bytes 16..31) -- per-frame status descriptor:
//     bytes 16..19  drop_count (records dropped on FIFO-full since reset)
//     bytes 20..23  frame_seq  (running frame number, for host loss detection)
//     byte  24      flags: bit0 = partial/timeout-flushed, bit1 = drops seen
//     byte  25      header version (0x03)
//     bytes 26..31  reserved (zero)
//   bytes 32..      K x 32-byte records (v3 layout, all big-endian):
//                   REC_FIXED(8)  fixed tag, user-assigned
//                   srcIP(8) dstIP(8)  32-bit IPv4 right-aligned in a 64-bit field
//                     (high 4 bytes zero) for the gmap/GraphBLAS index
//                   word A = protoCode(4b) | srcPort(12b FloatingEncoder)
//                   word B = flagsCode(4b) | dstPort(12b FloatingEncoder)
//                   pktLen(4)  IP totalLen right-aligned in a 32-bit field
//                   protoCode one-hot {TCP,UDP,ICMP,other}; flagsCode {ACK,RST,SYN,FIN}
//
// The 32-byte prefix (1 record slot) keeps records aligned to the 64-byte beat
// grid: beat 0 = prefix + 1 record, every following beat = 2 records. The
// status descriptor lets downstream stages (traffic-matrix construction)
// order frames, detect loss, and gauge data completeness.
//
// Flush policy: emit when the frame holds MAX_RECORDS records (full frame,
// fixed size), or when records are pending and no new record arrived for
// FLUSH_TIMEOUT_CYCLES (partial tail frame, variable size).
//
// Extraction rules:
//   - only ethertype 0x0800 + IP version 4 produces a record; everything
//     else (ARP, IPv6, kernel chatter) is drained without a record
//   - srcIP/dstIP/protocol sit at IHL-independent offsets and are always
//     valid; ports are zeroed when IHL != 5 or protocol is not TCP/UDP
//   - if the record FIFO is full the record is dropped (never stall
//     ingress) and drop_count increments
//
// *************************************************************************
`timescale 1ns/1ps
module graph_aggregator #(
  parameter int        FLUSH_TIMEOUT_CYCLES = 250000,  // ~1 ms @ 250 MHz
  parameter int        MAX_FRAME_LEN        = 1488,    // <= 1500 MTU
  parameter int        RECORD_FIFO_DEPTH    = 512,     // power of 2
  parameter bit [47:0] ETH_DST_MAC          = 48'h02_11_22_33_44_55,
  parameter bit [47:0] ETH_SRC_MAC          = 48'h02_AA_BB_CC_DD_EE,
  parameter bit [15:0] ETH_TYPE             = 16'h88B5, // local experimental
  // v3 record bytes 0-7: fixed MsgHdr tag, big-endian (record byte 0 = REC_FIXED[63:56]),
  // so the constant reads left-to-right on the wire. 0x81 00 FD 00 00 00 00 01 =
  // {msg_type=1,route_type=8} msg_flags=0 payload_type=0xFD tuple_type=0 pid=0 act=1.
  parameter bit [63:0] REC_FIXED            = 64'h8100_FD00_0000_0001
) (
  input          s_axis_tvalid,
  input  [511:0] s_axis_tdata,
  input   [63:0] s_axis_tkeep,
  input          s_axis_tlast,
  output         s_axis_tready,

  output         m_axis_tvalid,
  output [511:0] m_axis_tdata,
  output  [63:0] m_axis_tkeep,
  output         m_axis_tlast,
  output  [15:0] m_axis_tuser_size,
  input          m_axis_tready,

  output  [31:0] drop_count,
  output  [31:0] frame_count,

  input          aclk,
  input          aresetn
);

  localparam int   PREFIX_LEN   = 32;  // link header (0..15) + status descriptor (16..31)
  localparam int   RECORD_LEN   = 32;
  localparam int   PREFIX_SLOTS = PREFIX_LEN / RECORD_LEN;                       // 1
  localparam int   MAX_RECORDS  = (MAX_FRAME_LEN - PREFIX_LEN) / RECORD_LEN;     // 45
  localparam int   MAX_BEATS    = (PREFIX_LEN + RECORD_LEN*MAX_RECORDS + 63)/64; // 23
  localparam int   FIFO_AW      = $clog2(RECORD_FIFO_DEPTH);
  localparam int   IDLE_W       = $clog2(FLUSH_TIMEOUT_CYCLES + 1);
  localparam [7:0] HDR_VERSION  = 8'h03;

  // -----------------------------------------------------------------------
  // Extractor: 5-tuple from the first beat of each packet
  // -----------------------------------------------------------------------
  assign s_axis_tready = 1'b1;  // drop semantics: never stall ingress

  reg in_packet;
  always @(posedge aclk) begin
    if (!aresetn) begin
      in_packet <= 1'b0;
    end
    else if (s_axis_tvalid) begin
      in_packet <= !s_axis_tlast;
    end
  end
  wire first_beat = s_axis_tvalid && !in_packet;

  // FloatingEncoder: compress a 16-bit port into a 12-bit float-like code
  // {exp[1:0], mantissa[9:0]}, value = mantissa << (exp*2). The exponent is the
  // magnitude of the top set bit; the shift steps by 2 so each exponent spans a
  // 2-bit window -- test bit pairs, priority high->low. Exact for 0..1023
  // (well-known ports), floors above that. v==0 lands in the else branch.
  function automatic [11:0] floating_encode (input [15:0] v);
    if      (v[15:14] != 2'b0) floating_encode = {2'd3, v[15:6]};
    else if (v[13:12] != 2'b0) floating_encode = {2'd2, v[13:4]};
    else if (v[11:10] != 2'b0) floating_encode = {2'd1, v[11:2]};
    else                       floating_encode = {2'd0, v[9:0]};
  endfunction

  // v3 protocol code: 4-bit one-hot (mirrors host encode_protocol_bits >> 12).
  function automatic [3:0] proto_encode (input [7:0] p);
    case (p)
      8'd6:    proto_encode = 4'b1000;  // TCP
      8'd17:   proto_encode = 4'b0100;  // UDP
      8'd1:    proto_encode = 4'b0010;  // ICMP
      default: proto_encode = 4'b0001;  // other
    endcase
  endfunction

  // v3 TCP-flags code: {ACK,RST,SYN,FIN} (mirrors host encode_tcp_flags >> 12).
  function automatic [3:0] flags_encode (input [7:0] f);
    flags_encode = {f[4], f[2], f[1], f[0]};  // ACK=0x10 RST=0x04 SYN=0x02 FIN=0x01
  endfunction

  // Byte k of the beat is tdata[8k +: 8]. Untagged frame: ethertype at
  // bytes 12-13, IPv4 header from byte 14, L4 ports from byte 34 (IHL=5).
  wire [15:0] eth_type_w = {s_axis_tdata[8*12 +: 8], s_axis_tdata[8*13 +: 8]};
  wire  [3:0] ip_version = s_axis_tdata[8*14+4 +: 4];
  wire  [3:0] ip_ihl     = s_axis_tdata[8*14 +: 4];
  wire  [7:0] ip_proto   = s_axis_tdata[8*23 +: 8];

  wire is_ipv4   = (eth_type_w == 16'h0800) && (ip_version == 4'd4);
  wire ports_ok  = (ip_ihl == 4'd5) && (ip_proto == 8'd6 || ip_proto == 8'd17);
  wire tcp_ok    = (ip_ihl == 4'd5) && (ip_proto == 8'd6);
  // TCP flags live at byte 47 (IHL=5): only valid if that byte is present.
  wire flags_ok  = tcp_ok && (!s_axis_tlast || s_axis_tkeep[47]);
  wire runt_ok   = !s_axis_tlast || s_axis_tkeep[37];  // need bytes 0..37
  wire rec_valid = first_beat && is_ipv4 && runt_ok;

  // Ports are big-endian in the packet; assemble MSB-first before encoding.
  wire [15:0] sport_be = {s_axis_tdata[8*34 +: 8], s_axis_tdata[8*35 +: 8]};
  wire [15:0] dport_be = {s_axis_tdata[8*36 +: 8], s_axis_tdata[8*37 +: 8]};
  wire [11:0] sport_fp = ports_ok ? floating_encode(sport_be) : 12'h0;
  wire [11:0] dport_fp = ports_ok ? floating_encode(dport_be) : 12'h0;

  // v3 32-byte record (network order, byte j = rec[8j +: 8]):
  //   REC_FIXED(8) srcIP64(8) dstIP64(8) | protoCode|sPort, flagsCode|dPort (4) | pktLen32(4)
  // IPs and pktLen are right-aligned big-endian (value in the low bytes, high bytes zero).
  wire [3:0]  proto_fp = proto_encode(ip_proto);
  wire [3:0]  flags_fp = flags_ok ? flags_encode(s_axis_tdata[8*47 +: 8]) : 4'h0;

  wire [255:0] rec;
  assign rec[8*0  +: 8]  = REC_FIXED[63:56];                   // byte 0  MsgHdr tag (big-endian)
  assign rec[8*1  +: 8]  = REC_FIXED[55:48];                   // byte 1
  assign rec[8*2  +: 8]  = REC_FIXED[47:40];                   // byte 2
  assign rec[8*3  +: 8]  = REC_FIXED[39:32];                   // byte 3
  assign rec[8*4  +: 8]  = REC_FIXED[31:24];                   // byte 4
  assign rec[8*5  +: 8]  = REC_FIXED[23:16];                   // byte 5
  assign rec[8*6  +: 8]  = REC_FIXED[15:8];                    // byte 6
  assign rec[8*7  +: 8]  = REC_FIXED[7:0];                     // byte 7
  assign rec[8*8  +: 32] = 32'h0;                              // bytes 8-11  srcIP high pad
  assign rec[8*12 +: 32] = s_axis_tdata[8*26 +: 32];          // bytes 12-15 srcIP (BE)
  assign rec[8*16 +: 32] = 32'h0;                              // bytes 16-19 dstIP high pad
  assign rec[8*20 +: 32] = s_axis_tdata[8*30 +: 32];          // bytes 20-23 dstIP (BE)
  assign rec[8*24 +: 8]  = {proto_fp, sport_fp[11:8]};        // byte 24     word A high
  assign rec[8*25 +: 8]  = sport_fp[7:0];                      // byte 25     word A low
  assign rec[8*26 +: 8]  = {flags_fp, dport_fp[11:8]};        // byte 26     word B high
  assign rec[8*27 +: 8]  = dport_fp[7:0];                      // byte 27     word B low
  assign rec[8*28 +: 16] = 16'h0;                             // bytes 28-29 pktLen high pad
  assign rec[8*30 +: 16] = s_axis_tdata[8*16 +: 16];         // bytes 30-31 pktLen = totalLen (BE)

  // -----------------------------------------------------------------------
  // Record FIFO: simple synchronous show-ahead FIFO (distributed RAM).
  // Hand-rolled instead of xpm_fifo_sync so simulation does not depend on
  // the Vivado XPM libraries.
  // -----------------------------------------------------------------------
  reg  [255:0] fifo_mem [0:RECORD_FIFO_DEPTH-1];
  reg  [FIFO_AW:0] fifo_wr_ptr, fifo_rd_ptr;

  wire fifo_full  = (fifo_wr_ptr - fifo_rd_ptr) == RECORD_FIFO_DEPTH[FIFO_AW:0];
  wire fifo_empty = fifo_wr_ptr == fifo_rd_ptr;
  wire fifo_push  = rec_valid && !fifo_full;
  wire fifo_pop;
  wire [255:0] fifo_dout = fifo_mem[fifo_rd_ptr[FIFO_AW-1:0]];

  always @(posedge aclk) begin
    if (!aresetn) begin
      fifo_wr_ptr <= '0;
      fifo_rd_ptr <= '0;
    end
    else begin
      if (fifo_push) begin
        fifo_mem[fifo_wr_ptr[FIFO_AW-1:0]] <= rec;
        fifo_wr_ptr <= fifo_wr_ptr + 1'b1;
      end
      if (fifo_pop) begin
        fifo_rd_ptr <= fifo_rd_ptr + 1'b1;
      end
    end
  end

  reg [31:0] drop_cnt;
  always @(posedge aclk) begin
    if (!aresetn) begin
      drop_cnt <= '0;
    end
    else if (rec_valid && fifo_full && drop_cnt != '1) begin
      drop_cnt <= drop_cnt + 1'b1;  // saturating
    end
  end
  assign drop_count = drop_cnt;

  // -----------------------------------------------------------------------
  // Packetizer: fill the frame buffer one record per cycle, then drain it
  // to the host. Record k lives at frame bytes 32+32k, i.e. 32-byte slot
  // (k+1): beat (k+1)/2, slot (k+1)%2 -- the prefix occupies slot 0.
  // -----------------------------------------------------------------------
  localparam [1:0] ST_FILL  = 2'd0,
                   ST_PREP  = 2'd1,
                   ST_DRAIN = 2'd2;

  reg        [1:0] state;
  reg      [511:0] frame_buf [0:MAX_BEATS-1];
  reg        [6:0] rec_cnt;
  reg [IDLE_W-1:0] idle_cnt;
  reg        [4:0] beat_idx;
  reg        [4:0] last_beat;
  reg       [15:0] frame_len;
  reg       [31:0] frame_cnt;

  wire [6:0] slot_lin = rec_cnt + PREFIX_SLOTS[6:0];  // records start after prefix
  wire [4:0] wr_beat  = slot_lin[5:1];                // 2 x 256b slots per 512b beat
  wire       wr_slot  = slot_lin[0];

  assign fifo_pop = (state == ST_FILL) && !fifo_empty
                    && (rec_cnt < MAX_RECORDS[6:0]);

  wire [15:0] rec_cnt_w   = {9'd0, rec_cnt};
  wire [15:0] frame_len_w = PREFIX_LEN[15:0] + {rec_cnt_w[10:0], 5'd0};  // 32 + 32K

  wire drain_done = (state == ST_DRAIN) && m_axis_tready
                    && (beat_idx == last_beat);

  always @(posedge aclk) begin
    if (!aresetn) begin
      state     <= ST_FILL;
      rec_cnt   <= '0;
      idle_cnt  <= '0;
      beat_idx  <= '0;
      last_beat <= '0;
      frame_len <= '0;
      frame_cnt <= '0;
      // Deterministic buffer content: avoids X-propagation in simulation
      // and stale-data bytes in the tkeep-masked tail of partial frames
      for (int b = 0; b < MAX_BEATS; b++) begin
        frame_buf[b] <= '0;
      end
    end
    else begin
      case (state)
        ST_FILL: begin
          if (fifo_pop) begin
            frame_buf[wr_beat][256*wr_slot +: 256] <= fifo_dout;
            rec_cnt  <= rec_cnt + 1'b1;
            idle_cnt <= '0;
          end
          else if (rec_cnt != '0) begin
            idle_cnt <= idle_cnt + 1'b1;
          end

          if ((rec_cnt == MAX_RECORDS[6:0])
              || (rec_cnt != '0 && idle_cnt >= FLUSH_TIMEOUT_CYCLES[IDLE_W-1:0])) begin
            state <= ST_PREP;
          end
        end

        ST_PREP: begin
          // Ethernet header + record count, network byte order
          frame_buf[0][8*0  +: 8] <= ETH_DST_MAC[47:40];
          frame_buf[0][8*1  +: 8] <= ETH_DST_MAC[39:32];
          frame_buf[0][8*2  +: 8] <= ETH_DST_MAC[31:24];
          frame_buf[0][8*3  +: 8] <= ETH_DST_MAC[23:16];
          frame_buf[0][8*4  +: 8] <= ETH_DST_MAC[15:8];
          frame_buf[0][8*5  +: 8] <= ETH_DST_MAC[7:0];
          frame_buf[0][8*6  +: 8] <= ETH_SRC_MAC[47:40];
          frame_buf[0][8*7  +: 8] <= ETH_SRC_MAC[39:32];
          frame_buf[0][8*8  +: 8] <= ETH_SRC_MAC[31:24];
          frame_buf[0][8*9  +: 8] <= ETH_SRC_MAC[23:16];
          frame_buf[0][8*10 +: 8] <= ETH_SRC_MAC[15:8];
          frame_buf[0][8*11 +: 8] <= ETH_SRC_MAC[7:0];
          frame_buf[0][8*12 +: 8] <= ETH_TYPE[15:8];
          frame_buf[0][8*13 +: 8] <= ETH_TYPE[7:0];
          frame_buf[0][8*14 +: 8] <= rec_cnt_w[15:8];
          frame_buf[0][8*15 +: 8] <= rec_cnt_w[7:0];
          // Slot 1 (bytes 16..31): per-frame status descriptor.
          frame_buf[0][8*16 +: 8] <= drop_cnt[31:24];   // drop_count (cumulative)
          frame_buf[0][8*17 +: 8] <= drop_cnt[23:16];
          frame_buf[0][8*18 +: 8] <= drop_cnt[15:8];
          frame_buf[0][8*19 +: 8] <= drop_cnt[7:0];
          frame_buf[0][8*20 +: 8] <= frame_cnt[31:24];  // frame_seq
          frame_buf[0][8*21 +: 8] <= frame_cnt[23:16];
          frame_buf[0][8*22 +: 8] <= frame_cnt[15:8];
          frame_buf[0][8*23 +: 8] <= frame_cnt[7:0];
          frame_buf[0][8*24 +: 8] <= {6'b0, (drop_cnt != 32'd0),
                                            (rec_cnt != MAX_RECORDS[6:0])}; // flags
          frame_buf[0][8*25 +: 8] <= HDR_VERSION;
          frame_buf[0][8*26 +: 8] <= 8'h0;              // reserved
          frame_buf[0][8*27 +: 8] <= 8'h0;
          frame_buf[0][8*28 +: 8] <= 8'h0;
          frame_buf[0][8*29 +: 8] <= 8'h0;
          frame_buf[0][8*30 +: 8] <= 8'h0;
          frame_buf[0][8*31 +: 8] <= 8'h0;

          frame_len <= frame_len_w;
          last_beat <= ((frame_len_w - 1'b1) >> 6);
          beat_idx  <= '0;
          idle_cnt  <= '0;
          state     <= ST_DRAIN;
        end

        ST_DRAIN: begin
          if (m_axis_tready) begin
            if (beat_idx == last_beat) begin
              state     <= ST_FILL;
              rec_cnt   <= '0;
              frame_cnt <= frame_cnt + 1'b1;
            end
            else begin
              beat_idx <= beat_idx + 1'b1;
            end
          end
        end

        default: begin
          state <= ST_FILL;
        end
      endcase
    end
  end

  // Last-beat byte enables: frame_len[5:0] valid bytes (0 means all 64)
  wire [5:0]  tail_bytes = frame_len[5:0];
  wire [63:0] tail_keep  = (tail_bytes == 6'd0) ? {64{1'b1}}
                                                : ~({64{1'b1}} << tail_bytes);

  assign m_axis_tvalid     = (state == ST_DRAIN);
  assign m_axis_tdata      = frame_buf[beat_idx];
  assign m_axis_tlast      = (state == ST_DRAIN) && (beat_idx == last_beat);
  assign m_axis_tkeep      = m_axis_tlast ? tail_keep : {64{1'b1}};
  assign m_axis_tuser_size = frame_len;

  assign frame_count = frame_cnt;

endmodule: graph_aggregator
