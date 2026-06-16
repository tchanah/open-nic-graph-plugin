// *************************************************************************
//
// Simulation-only stand-ins for Vivado-generated components, so the
// cocotb testbench runs on open-source simulators (Icarus/Verilator)
// without the Vivado IP / XPM simulation libraries.
//
// These files are NOT read by build_box_250mhz.tcl: synthesis uses the
// real Xilinx axis_register_slice IP (src/utility/vivado_ip/
// axi_stream_pipeline.tcl) and the real XPM macros.
//
// *************************************************************************
`timescale 1ns/1ps

// Behavioral model of the "axi_stream_pipeline" axis_register_slice IP
// (512-bit TDATA, 64-bit TKEEP, 48-bit TUSER). Two-deep skid buffer with
// full AXI-Stream handshake compliance.
module axi_stream_pipeline (
  input          s_axis_tvalid,
  input  [511:0] s_axis_tdata,
  input   [63:0] s_axis_tkeep,
  input          s_axis_tlast,
  input   [47:0] s_axis_tuser,
  output         s_axis_tready,

  output         m_axis_tvalid,
  output [511:0] m_axis_tdata,
  output  [63:0] m_axis_tkeep,
  output         m_axis_tlast,
  output  [47:0] m_axis_tuser,
  input          m_axis_tready,

  input          aclk,
  input          aresetn
);

  localparam W = 48 + 1 + 64 + 512;  // {tuser, tlast, tkeep, tdata}

  reg [W-1:0] buf0;  // output stage
  reg [W-1:0] buf1;  // skid stage
  reg v0, v1;

  wire [W-1:0] s_pay = {s_axis_tuser, s_axis_tlast, s_axis_tkeep, s_axis_tdata};

  assign s_axis_tready = !v1;
  assign m_axis_tvalid = v0;
  assign {m_axis_tuser, m_axis_tlast, m_axis_tkeep, m_axis_tdata} = buf0;

  always @(posedge aclk) begin
    if (!aresetn) begin
      v0 <= 1'b0;
      v1 <= 1'b0;
    end
    else begin
      if (!v0 || m_axis_tready) begin
        // Output stage drains (or is empty): refill from skid, then input
        if (v1) begin
          buf0 <= buf1;
          v0   <= 1'b1;
          v1   <= 1'b0;
        end
        else if (s_axis_tvalid && !v1) begin
          buf0 <= s_pay;
          v0   <= 1'b1;
        end
        else begin
          v0 <= 1'b0;
        end
      end
      else if (s_axis_tvalid && !v1) begin
        // Output stage stalled and full: catch the in-flight beat
        buf1 <= s_pay;
        v1   <= 1'b1;
      end
    end
  end

endmodule

// Behavioral model of the XPM single-bit CDC synchronizer used by
// generic_reset. Parameter names match the real XPM macro.
module xpm_cdc_single #(
  parameter int DEST_SYNC_FF   = 4,
  parameter int INIT_SYNC_FF   = 0,
  parameter int SIM_ASSERT_CHK = 0,
  parameter int SRC_INPUT_REG  = 1
) (
  input  src_clk,
  input  src_in,
  input  dest_clk,
  output dest_out
);

  reg                    src_q  = 1'b0;
  reg [DEST_SYNC_FF-1:0] sync_q = '0;

  always @(posedge src_clk) begin
    src_q <= src_in;
  end

  wire src_w = (SRC_INPUT_REG != 0) ? src_q : src_in;

  always @(posedge dest_clk) begin
    sync_q <= {sync_q[DEST_SYNC_FF-2:0], src_w};
  end

  assign dest_out = sync_q[DEST_SYNC_FF-1];

endmodule
