# Program the Alveo U250 with the graph-plugin bitfile via JTAG.
# Bitfile path comes from the BITFILE env var (set by program_fpga.sh);
# falls back to the graph_v2 build location.
if {[info exists env(BITFILE)]} {
    set bitfile $env(BITFILE)
} else {
    set bitfile "/home/chettige/research/open-nic-shell/build/au250_graph_v2/open_nic_shell/open_nic_shell.runs/impl_1/open_nic_shell.bit"
}

open_hw_manager
connect_hw_server -url localhost:3121
open_hw_target
current_hw_device [lindex [get_hw_devices] 0]
set_property PROGRAM.FILE $bitfile [current_hw_device]
program_hw_devices [current_hw_device]
close_hw_target
disconnect_hw_server
exit
