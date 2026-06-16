# Cocotb testbench for the graph plugin box_250mhz.
#
# Prerequisites (one-time):
#   sudo apt install iverilog
#   pip3 install cocotb cocotbext-axi scapy
#
# Run:
#   make
#
# Assumes open-nic-shell is checked out as a sibling of this plugin repo
# (override with: make SHELL_SRC=/path/to/open-nic-shell/src).

SIM ?= icarus
TOPLEVEL_LANG ?= verilog

PLUGIN_ROOT := $(abspath ../..)
SHELL_SRC   ?= $(abspath ../../../open-nic-shell/src)

VERILOG_SOURCES := \
	$(SHELL_SRC)/utility/generic_reset.sv \
	$(SHELL_SRC)/utility/axi_lite_register.sv \
	$(SHELL_SRC)/utility/axi_lite_slave.sv \
	$(PLUGIN_ROOT)/graph_aggregator.sv \
	$(PLUGIN_ROOT)/p2p_250mhz.sv \
	$(PWD)/sim_models.sv \
	$(PWD)/p2p_250mhz_wrapper.sv

# open_nic_shell_macros.vh lives in the shell src directory
COMPILE_ARGS += -I$(SHELL_SRC)

TOPLEVEL := p2p_250mhz_wrapper
MODULE   := test_graph_250mhz_wrapper

include $(shell cocotb-config --makefiles)/Makefile.sim
